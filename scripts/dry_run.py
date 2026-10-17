#!/usr/bin/env python3
"""End-to-end dry run of the triage pipeline without a real LLM or real sinks.

Composes a full pipeline run from local pieces:

1. Enqueues a canned over-threshold alert (a real TrustSight fp-2026-10-16
   ``niri-screenshare`` entry) into a temp SQLite queue.
2. Runs :func:`triage_agent.pipeline.process_job` with a
   :class:`triage_agent.backends.ReplayBackend` that replays a canned
   verdict.json instead of executing opencode.
3. Verifies the verdict through the REAL local harness CLI
   (``harness fp_agent_verify --verdict <file>``). This is the only stage
   that touches the network, and it only reads the public AUR RPC/API; it
   never touches GitHub, ntfy, or the feed sink.
4. FP mode: renders the expected PR with the real ``harness fp_agent_pr``
   and runs the PR backstop against a localhost stub GitHub API
   (``tests/stub_github.py``), seeded with exactly the rendered title and
   body. TP/ioc mode: renders the real alert envelope with
   ``harness fp_agent_alert`` and POSTs it to a localhost stub receiver.
5. Prints a stage-by-stage report; exits non-zero on any gate failure.

No GITHUB token, ntfy webhook, or feed key is required: the stub GitHub
server and the stub alert sink run in-process on 127.0.0.1, and the
backstop is given a dummy bearer token it never validates.

Usage (from the repo root)::

    uv run python scripts/dry_run.py --mode fp
    uv run python scripts/dry_run.py --mode ioc
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (str(ROOT), str(ROOT / "src")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

import httpx  # noqa: E402

from tests.stub_github import AlertSinkStub, GitHubApiStub  # noqa: E402
from triage_agent import pipeline, runner, special_alert  # noqa: E402
from triage_agent.backends import ReplayBackend  # noqa: E402
from triage_agent.config import Settings  # noqa: E402
from triage_agent.pr_backstop import check_pr, harness_render_pr  # noqa: E402
from triage_agent.queue import JobQueue  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
ALERT_FIXTURE = FIXTURES / "alert_niri_screenshare.json"
VERDICT_FIXTURES = {
    "fp": FIXTURES / "verdict_niri_screenshare_fp.json",
    "ioc": FIXTURES / "verdict_niri_screenshare_tp.json",
}
EXPECTED_STATUS = {"fp": "pr_opened", "ioc": "alert_sent"}

#: Dummy credential for the stub GitHub API; never validated, never real.
DRY_RUN_TOKEN = "dry-run-token"


@dataclass
class DryRunReport:
    mode: str
    workdir: Path
    stages: list[tuple[str, bool, str]] = field(default_factory=list)
    queue_status: str | None = None
    pr_url: str | None = None
    alert_received: bool = False

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.stages)

    def stage(self, name: str, ok: bool, detail: str) -> None:
        self.stages.append((name, ok, detail))

    def render(self) -> str:
        lines = [f"dry run (mode={self.mode}) workdir={self.workdir}"]
        for name, ok, detail in self.stages:
            mark = "ok" if ok else "FAIL"
            lines.append(f"  [{mark}] {name}: {detail}")
        verdict = "PASS" if self.ok else "FAIL"
        lines.append(f"queue status: {self.queue_status}; overall: {verdict}")
        return "\n".join(lines)


def harness_render_alert(
    verify_result: dict, *, cli: str = "harness", timeout: int = 900
) -> dict:
    """Render the confirmed-IOC alert envelope via ``harness fp_agent_alert``."""

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", encoding="utf-8", delete=False
    ) as handle:
        json.dump(verify_result, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [cli, "fp_agent_alert", "--result", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        raise RuntimeError(
            f"harness fp_agent_alert exited {proc.returncode}:"
            f" {proc.stderr.strip()[:512]}"
        )
    rendered = json.loads(proc.stdout)
    if isinstance(rendered, dict) and "error" in rendered:
        raise RuntimeError(f"harness fp_agent_alert: {rendered['error']}")
    return rendered


def run_dry_run(
    *,
    mode: str = "fp",
    cli: str = "harness",
    workdir: str | Path | None = None,
    verify=runner.harness_verify,
    render_pr=harness_render_pr,
    render_alert=harness_render_alert,
    emit=print,
) -> DryRunReport:
    """Run the dry run; returns a report (``report.ok`` is the gate verdict).

    *verify*, *render_pr*, and *render_alert* are injectable so the offline
    tests can substitute fakes; the defaults invoke the real harness CLI.
    """

    if mode not in VERDICT_FIXTURES:
        raise ValueError(f"mode must be one of {sorted(VERDICT_FIXTURES)}")
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="triage-dry-"))
    base.mkdir(parents=True, exist_ok=True)
    report = DryRunReport(mode=mode, workdir=base)

    settings = Settings(job_root=str(base / "jobs"), harness_cli=cli)
    entry = json.loads(ALERT_FIXTURE.read_text())
    payload = {
        "package": entry["package"],
        "old_version": entry.get("old_version"),
        "new_version": entry.get("new_version"),
        "aur_url": entry.get("aur_url"),
        "rules": entry.get("rules", []),
        "findings": entry.get("findings", []),
    }

    verdict = runner.load_verdict(VERDICT_FIXTURES[mode])

    with JobQueue(base / "triage.sqlite3") as queue:
        job, created = queue.enqueue(payload, package=entry["package"])
        report.stage(
            "enqueue", created, f"job {job.id} queued for {entry['package']}"
        )

        # Pre-verify once so the localhost stubs can be seeded with exactly
        # what the real harness renders, then hand process_job the cached
        # result; the pipeline under test stays process_job itself.
        try:
            result = verify(verdict, cli=cli, timeout=settings.harness_timeout_seconds)
            report.stage("verify", True, f"harness kind={result.get('kind')}")
        except Exception as exc:
            report.stage("verify", False, str(exc))
            result = None

        github = None
        sink = None
        stub_setup_ok = False
        if result is not None:
            try:
                if mode == "fp":
                    rendered = render_pr(result, target_repo="trustsight", cli=cli)
                    report.stage("render_pr", True, f"title={rendered['title']!r}")
                    github = GitHubApiStub(
                        pr={"title": rendered["title"], "body": rendered["body"]}
                    )
                    backend = ReplayBackend(
                        VERDICT_FIXTURES[mode], pr_url=github.pr_url
                    )
                    send = special_alert.send_alert
                else:
                    envelope = render_alert(result, cli=cli)
                    report.stage(
                        "render_alert", True, f"event={envelope.get('event')}"
                    )
                    sink = AlertSinkStub()
                    settings = Settings(
                        job_root=settings.job_root, ntfy_webhook=sink.url
                    )
                    backend = ReplayBackend(VERDICT_FIXTURES[mode])

                    def send(alert, _settings, **kwargs):
                        return special_alert.send_alert(
                            envelope, _settings, client=kwargs.get("client")
                        )
                stub_setup_ok = True
            except Exception as exc:
                report.stage("stubs", False, str(exc))
        else:
            report.stage("stubs", False, "verify did not produce a result")

        outcome = None
        if stub_setup_ok:
            with github or _nullctx(), sink or _nullctx():
                outcome = pipeline.process_job(
                    job_id=job.id,
                    payload=payload,
                    settings=settings,
                    queue=queue,
                    backend=backend,
                    verify=lambda verdict, **kwargs: result,
                    backstop=lambda cli=None, token=None, **kwargs: check_pr(
                        api_base=github.api_base,
                        token=DRY_RUN_TOKEN,
                        cli=cli or settings.harness_cli,
                        **kwargs,
                    ),
                    send=send,
                    http_client=httpx.Client(),
                )
                report.queue_status = queue.get(job.id).status

            if sink is not None:
                report.alert_received = bool(sink.received)

        if outcome is None:
            pass  # stub setup already failed above
        elif outcome.status == EXPECTED_STATUS[mode]:
            report.stage("pipeline", True, f"outcome={outcome.status}")
            if mode == "fp" and github is not None:
                closed = "no" if not github.patches else "yes"
                report.stage("backstop", True, f"PR matched; closed: {closed}")
                report.pr_url = outcome.pr_url
            if mode == "ioc":
                report.stage(
                    "alert_sink", report.alert_received,
                    f"envelope POSTed: {report.alert_received}",
                )
        else:
            report.stage(
                "pipeline", False, f"outcome={outcome.status}: {outcome.reason}"
            )
    emit(report.render())
    return report


class _nullctx:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--mode",
        choices=sorted(VERDICT_FIXTURES),
        default="fp",
        help="fp: FP path with PR backstop; ioc: TP/IOC alert path",
    )
    parser.add_argument("--cli", default="harness", help="harness CLI binary")
    parser.add_argument(
        "--workdir",
        default=None,
        help="scratch directory (default: a fresh tempfile, printed in report)",
    )
    args = parser.parse_args(argv)
    report = run_dry_run(mode=args.mode, cli=args.cli, workdir=args.workdir)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
