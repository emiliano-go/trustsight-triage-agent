"""Job pipeline composition.

:func:`process_job` wires the stages around :func:`runner.run_job`:
prompt build, agent run (the backend; the agent itself opens the PR through
the GitHub MCP tools), verdict validation and harness verification, then the
post-verification stages:

- FP: the PR backstop re-fetches the opened PR and compares it against the
  ``harness fp_agent_pr`` render; a mismatch closes the PR and fails the
  job; a missing PR fails the job too.
- TP: the confirmed-IOC alert (from ``harness fp_agent_alert``) is
  delivered through :mod:`special_alert`.

The PR URL the agent produced is read off the backend as ``last_pr_url``
when it exposes one; otherwise the job fails with ``no PR found``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from . import runner, special_alert
from .pr_backstop import check_pr
from .prompt import build_prompt
from .queue import JobQueue, TransitionError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineOutcome:
    status: str  # mirrors JobQueue statuses
    reason: str | None = None
    pr_url: str | None = None


def process_job(
    *,
    job_id: str,
    payload: dict,
    settings: object,
    queue: JobQueue,
    backend: runner.RunnerBackend,
    verify: object = runner.harness_verify,
    backstop: object = check_pr,
    send: object = special_alert.send_alert,
    http_client: object | None = None,
) -> PipelineOutcome:
    """Run one claimed job end to end, transitioning the queue record."""

    cli = getattr(settings, "harness_cli", "harness")
    timeout = getattr(settings, "harness_timeout_seconds", 900)

    try:
        queue.transition(job_id, "running")
    except TransitionError:
        pass  # already claimed

    prompt = build_prompt(payload)
    outcome = runner.run_job(
        job_id=job_id,
        prompt=prompt,
        job_root=getattr(settings, "job_root", "/job"),
        backend=backend,
        cli=cli,
        timeout=timeout,
        verify=verify,
    )

    if outcome.outcome == "failed":
        reason = outcome.reason or "agent run failed"
        queue.transition(job_id, "failed", error=reason)
        return PipelineOutcome(status="failed", reason=reason)
    if outcome.outcome == "needs_review":
        queue.transition(job_id, "needs_review")
        return PipelineOutcome(status="needs_review")

    verdict = outcome.verdict or {}
    result = outcome.verify_result or {}
    kind = result.get("kind") or verdict.get("verdict")

    queue.transition(job_id, "verified")

    if kind == "TP":
        try:
            alert = send(result, settings, client=http_client)
        except Exception as exc:
            alert = special_alert.AlertResult(reason=str(exc))
        if not (getattr(alert, "ntfy", False) or getattr(alert, "feed", False)):
            reason = f"alert delivery failed: {getattr(alert, 'reason', 'unknown')}"
            queue.transition(job_id, "failed", error=reason)
            return PipelineOutcome(status="failed", reason=reason)
        queue.transition(job_id, "alert_sent")
        return PipelineOutcome(status="alert_sent")

    if kind == "FP":
        pr_url = getattr(backend, "last_pr_url", None)
        if not pr_url:
            reason = "no PR found: agent did not report opening one"
            queue.transition(job_id, "failed", error=reason)
            return PipelineOutcome(status="failed", reason=reason)
        check = backstop(
            pr_url=pr_url,
            verify_result=result,
            token=getattr(settings, "github_token", None),
            client=http_client,
            cli=cli,
        )
        if not check.ok:
            reason = f"PR backstop: {check.reason}"
            queue.transition(job_id, "failed", error=reason)
            return PipelineOutcome(status="failed", reason=reason, pr_url=pr_url)
        queue.transition(job_id, "pr_opened", pr_url=pr_url)
        return PipelineOutcome(status="pr_opened", pr_url=pr_url)

    reason = f"unsupported verified kind: {kind!r}"
    queue.transition(job_id, "failed", error=reason)
    return PipelineOutcome(status="failed", reason=reason)
