"""Runner backends beyond the test stub.

``ReplayBackend`` replays a canned verdict.json instead of executing
opencode. It exists for dry runs (see ``scripts/dry_run.py``) and for
replaying recorded agent outputs in tests: strictly offline, it reads the
canned verdict from a fixture path and exposes ``last_pr_url`` so the FP
backstop stage in :func:`triage_agent.pipeline.process_job` can run.
"""

from __future__ import annotations

from pathlib import Path

from .queue import write_job_file
from .runner import VerdictError


class ReplayBackend:
    """Replay a canned verdict file as if the agent had written it.

    Args:
        verdict_path: File whose bytes become the job's verdict.json.
        pr_url: Fake PR URL to report as ``last_pr_url`` (FP path only);
            outside tests this may be any marker string, e.g. a stub-server
            URL. ``None`` makes the pipeline fail at "no PR found".
    """

    def __init__(self, verdict_path: str | Path, *, pr_url: str | None = None):
        self.verdict_path = Path(verdict_path)
        self.last_pr_url = pr_url
        self.calls: list[dict] = []

    def run(self, *, prompt: str, job_id: str, job_root: str) -> Path:
        if not self.verdict_path.is_file():
            raise VerdictError(f"canned verdict not found: {self.verdict_path}")
        self.calls.append({"prompt": prompt, "job_id": job_id})
        data = self.verdict_path.read_bytes()
        return write_job_file(job_root, job_id, "verdict.json", data)
