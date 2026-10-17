"""In-container agent job: run opencode with retry classification.

This is the command the Docker backend runs inside the job container
(``triage-agent agent-job``), reduced to what must happen *inside* the
sandbox:

1. Read the prompt the backend mounted at ``/job/prompt.txt``.
2. Run the real opencode CLI (``agent/opencode.json``: MiMo-V2.6 flash-free
   model route, harness-mcp + github-mcp-server, no bash/edit/write tools).
   opencode's own session layer retries transient provider errors a few
   times, but its retry policy is internal, unconfigurable, and gives up
   into a generic ``UnknownError`` for several failure shapes (see opencode
   issue #17648), so this module adds a coarse second layer:
   ``classify_failure`` buckets the combined output into ``rate_limited``
   (the backend reacts by starting a fresh container, which is the egress
   rotation), ``transient`` (retried in place with the shared
   ``BackoffSchedule``, at most ``MAX_IN_PLACE_RETRIES`` attempts), and
   ``fatal`` (fail fast). WARP egress is ambient by the time we run: the
   entrypoint registered and connected warp-svc before exec'ing us.
3. Extract the verdict JSON from the agent's final message and write it to
   ``/job/verdict.json`` (the opencode write tool is disabled by contract,
   so this module owns the file write). Extract a reported PR URL, if any,
   to ``/job/pr_url`` so the pipeline's backstop can use it as a fast path.
4. Exit codes: 0 success; 1 failure (message on stderr); 3 rate-limited,
   telling the backend to rotate egress (fresh container) without burning
   an in-place retry.

Environment: ``TRIAGE_MODEL`` (default opencode/mimo-v2.6-flash-free),
``OPENCODE_BIN`` (default ``opencode``), ``AGENT_JOB_TIMEOUT_SECONDS``
(default 1200), ``TRIAGE_REPO_ROOT`` (default ``/app/trustsight-triage-agent``,
where ``agent/opencode.json`` lives in the image).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from .config import WarpSettings
from .rate_limit import detect_429, effective_delay, extract_retry_after

DEFAULT_MODEL = "opencode/mimo-v2.6-flash-free"
DEFAULT_TIMEOUT = 1200
MAX_IN_PLACE_RETRIES = 3
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_RATE_LIMITED = 3
PROMPT_PATH = Path("/job/prompt.txt")
VERDICT_PATH = Path("/job/verdict.json")
PR_URL_PATH = Path("/job/pr_url")
OUTPUT_PATH = Path("/job/agent-output.txt")
MAX_OUTPUT_CHARS = 500_000

_PR_URL_RE = re.compile(r"https://github\.com/[^/\s]+/[^/\s]+/pull/\d+")

#: Transient provider/server fault shapes worth retrying in place. Mirrors
#: the classification opencode's own SessionRetry uses, so the second layer
#: only fires where the first gave up or died without retrying.
_TRANSIENT_RE = re.compile(
    r"unexpected server error|unknownerror|server error|internal error"
    r"|\b5\d\d\b|bad gateway|gateway timeout|service unavailable"
    r"|overloaded|at capacity|try again|try your request again"
    r"|fetch failed|network[-_\s]error|connection (error|refused|lost|reset)"
    r"|socket hang up|econnreset|econnrefused|etimedout|enotfound|eai_again"
    r"|timed? ?out|stream (error|closed|disconnected)",
    re.IGNORECASE,
)


def classify_failure(output: str) -> str:
    """Bucket combined opencode output: rate_limited | transient | fatal."""

    if detect_429(output):
        return "rate_limited"
    if _TRANSIENT_RE.search(output or ""):
        return "transient"
    return "fatal"


def extract_verdict(output: str) -> dict | None:
    """Last JSON object in the output that looks like a verdict.

    Decodes from every ``{`` position (nested objects break naive
    brace-matching regexes), so any embedded JSON is handled.
    """

    decoder = json.JSONDecoder()
    best = None
    for index, char in enumerate(output):
        if char != "{":
            continue
        try:
            doc, _ = decoder.raw_decode(output[index:])
        except ValueError:
            continue
        if (
            isinstance(doc, dict)
            and doc.get("schema_version") == 1
            and "verdict" in doc
            and "package" in doc
        ):
            best = doc
    return best


def extract_pr_url(output: str) -> str | None:
    matches = _PR_URL_RE.findall(output)
    return matches[-1] if matches else None


def run_agent(
    prompt: str,
    *,
    model: str,
    opencode: str,
    config: Path,
    cwd: Path,
    timeout: int,
    runner: object = subprocess.run,
) -> tuple[str, int]:
    """One opencode invocation; returns (combined output, exit code)."""

    proc = runner(
        # --auto approves permission prompts headlessly; the agent config
        # explicitly denies bash/edit/write, and those denies win. Without
        # it every gated tool call (e.g. read outside the cwd) is
        # auto-rejected and the turn dies with no verdict.
        [opencode, "run", "--auto", "-c", str(config), "--agent", "triage",
         "-m", model, prompt],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(cwd),
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return output, proc.returncode


def run_with_retries(
    prompt: str,
    *,
    model: str,
    opencode: str,
    config: Path,
    cwd: Path,
    timeout: int,
    runner: object = subprocess.run,
    sleeper: object = time.sleep,
    log=print,
) -> tuple[str, int]:
    """Run opencode, retrying transient failures in place.

    Rate-limit failures and fatal errors return immediately so the caller
    can route them (exit 3 rotates egress in the backend); only transient
    faults spend the in-place retry budget.
    """

    schedule = WarpSettings().schedule()
    last_output = ""
    for attempt in range(1, MAX_IN_PLACE_RETRIES + 1):
        try:
            output, rc = run_agent(
                prompt, model=model, opencode=opencode, config=config,
                cwd=cwd, timeout=timeout, runner=runner,
            )
        except subprocess.TimeoutExpired as exc:
            # Keep whatever the agent printed before the kill: it is the
            # only evidence of where a long turn spent its time.
            partial = ((exc.stdout or "") if isinstance(exc.stdout, str)
                       else (exc.stdout or b"").decode("utf-8", "replace"))
            partial += ((exc.stderr or "") if isinstance(exc.stderr, str)
                        else (exc.stderr or b"").decode("utf-8", "replace"))
            output, rc = (partial
                          + f"\nopencode timed out after {timeout}s"), -1
        except OSError as exc:
            print(f"agent-job: opencode failed to start: {exc}",
                  file=sys.stderr)
            return "", EXIT_FAILURE
        last_output = output
        if rc == 0:
            return output, EXIT_OK
        kind = classify_failure(output)
        tail = output.strip()[-300:]
        log(f"agent-job: attempt {attempt}/{MAX_IN_PLACE_RETRIES} failed "
            f"(rc={rc}, class={kind}): {tail}", file=sys.stderr)
        if kind != "transient":
            return output, EXIT_RATE_LIMITED if kind == "rate_limited" \
                else EXIT_FAILURE
        if attempt < MAX_IN_PLACE_RETRIES:
            # Floor the schedule delay with any Retry-After hint the provider
            # echoed into the output; opencode swallows response headers, so
            # this is best-effort and the schedule is the default.
            delay = effective_delay(
                schedule, attempt, extract_retry_after(output)
            )
            log(f"agent-job: transient failure; retrying in {delay}s",
                file=sys.stderr)
            sleeper(delay)
    return last_output, EXIT_FAILURE


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    model = os.environ.get("TRIAGE_MODEL", "").strip() or DEFAULT_MODEL
    opencode = os.environ.get("OPENCODE_BIN", "").strip() or "opencode"
    timeout = int(os.environ.get("AGENT_JOB_TIMEOUT_SECONDS", "")
                  or DEFAULT_TIMEOUT)
    repo_root = Path(
        os.environ.get("TRIAGE_REPO_ROOT", "/app/trustsight-triage-agent")
    )
    config = repo_root / "agent" / "opencode.json"
    cwd = Path(os.environ.get("HOME", "/tmp"))

    prompt_path = Path(argv[0]) if argv else PROMPT_PATH
    try:
        prompt = prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"agent-job: cannot read {prompt_path}: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    output, rc = run_with_retries(
        prompt, model=model, opencode=opencode, config=config,
        cwd=cwd, timeout=timeout,
    )
    # Always persist the raw agent output (bounded): the job volume is
    # destroyed after collection, and it is the only record of what the
    # model did, including PR steps that never happened.
    OUTPUT_PATH.write_text(output[-MAX_OUTPUT_CHARS:])
    if rc == EXIT_RATE_LIMITED:
        print("agent-job: rate limited; signaling egress rotation",
              file=sys.stderr)
        return EXIT_RATE_LIMITED
    if rc != EXIT_OK:
        tail = output.strip()[-500:]
        print(f"agent-job: opencode failed: {tail}", file=sys.stderr)
        return EXIT_FAILURE

    verdict = extract_verdict(output)
    if verdict is None:
        tail = output.strip()[-2000:]
        print(f"agent-job: no verdict JSON in agent output; tail:\n{tail}",
              file=sys.stderr)
        return EXIT_FAILURE
    VERDICT_PATH.write_text(json.dumps(verdict, indent=2, sort_keys=True))
    pr_url = extract_pr_url(output)
    if pr_url:
        PR_URL_PATH.write_text(pr_url + "\n")
    print(
        f"agent-job: verdict={verdict['verdict']} "
        f"confidence={verdict['confidence']}"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
