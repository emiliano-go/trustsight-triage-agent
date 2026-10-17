"""Multi-package pipeline: one alert, one aggregate FP PR, mixed verdicts."""

from __future__ import annotations

import json
import re

import pytest

from triage_agent import pipeline, special_alert
from triage_agent.config import Settings
from triage_agent.queue import JobQueue

PR_URL = "https://github.com/acme/trustsight/pull/99"

_PACKAGES = [
    {"package": "pkg-a", "aur_url": "https://aur.archlinux.org/packages/pkg-a",
     "old_version": "1.0-1", "new_version": "1.1-1",
     "rules": ["C024"], "findings": [], "alert_slug": "2026-10-17/000001"},
    {"package": "pkg-b", "aur_url": "https://aur.archlinux.org/packages/pkg-b",
     "old_version": "2.0-1", "new_version": "2.1-1",
     "rules": ["C024"], "findings": [], "alert_slug": "2026-10-17/000001"},
    {"package": "pkg-c", "aur_url": "https://aur.archlinux.org/packages/pkg-c",
     "old_version": "3.0-1", "new_version": "3.1-1",
     "rules": ["C024"], "findings": [], "alert_slug": "2026-10-17/000001"},
]

_PROMPT_PKG_RE = re.compile(r"for the AUR package\n'([^']+)'")


class MultiStubBackend:
    """Per-package verdicts keyed by the package named in the prompt."""

    def __init__(self, verdicts: dict[str, dict]):
        self._verdicts = verdicts
        self.calls: list[dict] = []

    def run(self, *, prompt: str, job_id: str, job_root: str):
        from triage_agent.queue import write_job_file

        self.calls.append({"prompt": prompt, "job_id": job_id})
        match = _PROMPT_PKG_RE.search(prompt)
        assert match, f"prompt names no package: {prompt[:200]!r}"
        verdict = self._verdicts[match.group(1)]
        data = json.dumps(verdict, indent=2).encode()
        return write_job_file(job_root, job_id, "verdict.json", data)


def _verdict(package: str, verdict: str, confidence: str = "high") -> dict:
    return {"schema_version": 1, "package": package, "verdict": verdict,
            "confidence": confidence, "rationale": "checked",
            "evidence": {}, "proposed_changes": {}}


def _verify(verdict: dict, **kwargs):
    package = verdict["package"]
    if verdict["verdict"] == "TP":
        return {"kind": "TP", "verified": True, "package": package,
                "rationale": "confirmed", "version_transition": "1 to 2",
                "ioc_entries": [{"type": "domain", "value": f"{package}.evil",
                                 "confidence": "high",
                                 "provenance": "checked"}]}
    return {"kind": "FP", "verified": True, "package": package,
            "findings_table": [
                {"finding": f"{package} noise", "false_trigger": "t",
                 "fix": "f"}],
            "suppression": {"rule_id": "C024", "package": package},
            "report_entry": {"package": package}}


class FakeRender:
    """Mirrors the harness fp_agent_pr multi-package FP render."""

    def __init__(self):
        self.calls: list[dict] = []

    def __call__(self, result, *, target_repo="trustsight", **kwargs):
        self.calls.append(result)
        if "packages" in result:
            names = [p["package"] for p in result["packages"]]
            head = ", ".join(names[:2])
            if len(names) > 2:
                head += f" (+{len(names) - 2} more)"
            body_lines = [f"FP triage: {head}", ""]
            files = {}
            for item in result["packages"]:
                name = item["package"]
                body_lines += [f"Package: {name}",
                               "| Finding | False trigger | Fix |",
                               "|---|---|---|",
                               f"| {name} noise | t | f |", ""]
                files[f"data/fp-suppressions/2026-10-17-{name}.json"] = \
                    json.dumps(item["suppression"]) + "\n"
            return {"branch": "triage/fp-multi-deadbeef",
                    "title": f"FP triage: {head}",
                    "body": "\n".join(body_lines),
                    "files": files}
        name = result["package"]
        return {"branch": f"triage/ioc-{name}-deadbeef",
                "title": f"IOC report: {name}",
                "body": "| Type | Value | Confidence |\n",
                "files": {f"data/iocs/triage-2026-10-17-{name}.json":
                          json.dumps(result["ioc_entries"]) + "\n"}}


class _Ok:
    ok = True
    reason = None
    pr_url = None


@pytest.fixture()
def queue(tmp_path):
    with JobQueue(tmp_path / "triage.sqlite3") as q:
        yield q


def _run(tmp_path, queue, backend, monkeypatch, render=None, sent=None,
         opened=None, backstop_results=None):
    settings = Settings(job_root=str(tmp_path / "jobs"),
                        github_token="tok", github_owner="acme")
    job, _ = queue.enqueue({"packages": _PACKAGES},
                           package="pkg-a (+2 more)")
    render = render or FakeRender()
    opened = opened if opened is not None else []
    sent = sent if sent is not None else []

    def fake_open(**kwargs):
        opened.append(kwargs["rendered"])
        return PR_URL

    def fake_send(alert, settings, **kwargs):
        sent.append(alert)
        return special_alert.AlertResult(ntfy=True)

    monkeypatch.setattr(
        special_alert, "harness_alert",
        lambda result, **kw: {"event": "trustsight.confirmed-ioc",
                              "package": result["package"]},
    )
    outcome = pipeline.process_job(
        job_id=job.id,
        payload={"packages": _PACKAGES},
        settings=settings,
        queue=queue,
        backend=backend,
        verify=_verify,
        backstop=lambda **k: _Ok(),
        send=fake_send,
        pr_open=fake_open,
        render=render,
    )
    return outcome, render, opened, sent, job


def test_three_fp_packages_one_pr_with_three_suppressions(
        tmp_path, queue, monkeypatch):
    backend = MultiStubBackend({p: _verdict(p, "FP") for p in
                                ("pkg-a", "pkg-b", "pkg-c")})
    outcome, render, opened, sent, job = _run(
        tmp_path, queue, backend, monkeypatch)

    assert outcome.status == "pr_opened"
    assert outcome.pr_url == PR_URL
    assert queue.get(job.id).status == "pr_opened"
    # One agent run per package, sequentially, and each prompt must be the
    # analysis variant that forbids opening PRs.
    assert len(backend.calls) == 3
    assert all("Do NOT use any github tool" in c["prompt"]
               for c in backend.calls)
    # The aggregate FP render covered all three packages ...
    aggregate = render.calls[-1]
    assert [p["package"] for p in aggregate["packages"]] == [
        "pkg-a", "pkg-b", "pkg-c"]
    # ... produced exactly one PR ...
    assert len(opened) == 1
    pr = opened[0]
    assert pr["title"] == "FP triage: pkg-a, pkg-b (+1 more)"
    assert list(pr["files"]) == [
        "data/fp-suppressions/2026-10-17-pkg-a.json",
        "data/fp-suppressions/2026-10-17-pkg-b.json",
        "data/fp-suppressions/2026-10-17-pkg-c.json",
    ]
    # ... with one findings-table section per package.
    assert pr["body"].count("| Finding | False trigger | Fix |") == 3
    for pkg in ("pkg-a", "pkg-b", "pkg-c"):
        assert f"Package: {pkg}" in pr["body"]
    # No TP packages: no alerts, no IOC PRs.
    assert sent == []
    assert all("iocs" not in path for pr in opened
               for path in pr["files"])


def test_mixed_verdicts_split_flows(tmp_path, queue, monkeypatch):
    backend = MultiStubBackend({
        "pkg-a": _verdict("pkg-a", "FP"),
        "pkg-b": _verdict("pkg-b", "TP"),
        "pkg-c": _verdict("pkg-c", "uncertain", confidence="medium"),
    })
    outcome, render, opened, sent, job = _run(
        tmp_path, queue, backend, monkeypatch)

    assert outcome.status == "pr_opened"
    # FP packages went into the aggregate PR only; the TP package got its
    # own IOC register PR.
    aggregate = render.calls[-1]
    assert [p["package"] for p in aggregate["packages"]] == ["pkg-a"]
    assert len(opened) == 2
    fp_prs = [pr for pr in opened if "fp-suppressions" in next(iter(pr["files"]))]
    assert len(fp_prs) == 1
    assert list(fp_prs[0]["files"]) == [
        "data/fp-suppressions/2026-10-17-pkg-a.json"]
    # The TP package got the confirmed-IOC flow for that package only.
    assert [a["package"] for a in sent] == ["pkg-b"]
    assert sent[0]["event"] == "trustsight.confirmed-ioc"
    # The uncertain package produced no PR content and no alert.
    assert "pkg-c" not in json.dumps(opened)
    assert outcome.reason and "pkg-c" in outcome.reason
    assert queue.get(job.id).status == "pr_opened"


def test_tp_only_multi_job_sends_alerts_and_ioc_prs(
        tmp_path, queue, monkeypatch):
    backend = MultiStubBackend({p: _verdict(p, "TP") for p in
                                ("pkg-a", "pkg-b", "pkg-c")})
    outcome, render, opened, sent, job = _run(
        tmp_path, queue, backend, monkeypatch)

    assert outcome.status == "alert_sent"
    assert queue.get(job.id).status == "alert_sent"
    assert len(sent) == 3
    assert len(opened) == 3  # one IOC register PR per TP package
    assert all("data/iocs/" in next(iter(pr["files"])) for pr in opened)


def test_all_uncertain_multi_job_needs_review(tmp_path, queue, monkeypatch):
    backend = MultiStubBackend({p: _verdict(p, "uncertain", "medium")
                                for p in ("pkg-a", "pkg-b", "pkg-c")})
    outcome, render, opened, sent, job = _run(
        tmp_path, queue, backend, monkeypatch)

    assert outcome.status == "needs_review"
    assert queue.get(job.id).status == "needs_review"
    assert opened == []
    assert sent == []
    assert render.calls == []


def test_package_failure_fails_multi_job(tmp_path, queue, monkeypatch):
    class BrokenBackend:
        def run(self, *, prompt, job_id, job_root):
            raise RuntimeError("container exploded")

    settings = Settings(job_root=str(tmp_path / "jobs"),
                        github_token="tok", github_owner="acme")
    job, _ = queue.enqueue({"packages": _PACKAGES},
                           package="pkg-a (+2 more)")
    outcome = pipeline.process_job(
        job_id=job.id,
        payload={"packages": _PACKAGES},
        settings=settings,
        queue=queue,
        backend=BrokenBackend(),
        verify=_verify,
    )
    assert outcome.status == "failed"
    assert "container exploded" in outcome.reason
    assert queue.get(job.id).status == "failed"
