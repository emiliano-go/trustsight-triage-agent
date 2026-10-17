"""Job pipeline composition.

:func:`process_job` wires the stages around :func:`runner.run_job`:
prompt build, agent run (the backend; the agent itself opens the PR through
the GitHub MCP tools), verdict validation and harness verification, then the
post-verification stages:

- FP: the PR backstop re-fetches the opened PR and compares it against the
  ``harness fp_agent_pr`` render; the PR URL comes from the backend's
  ``last_pr_url`` (the agent's /job/pr_url artifact) when known, otherwise
  the backstop discovers it via the pulls list endpoint by the rendered
  branch; a mismatch closes the PR and fails the job; a missing PR fails
  the job too.
- TP: the confirmed-IOC alert (from ``harness fp_agent_alert``) is
  delivered through :mod:`special_alert`.

The PR URL the agent produced is read off the backend as ``last_pr_url``
when it exposes one (the in-container agent writes a /job/pr_url
artifact); otherwise the backstop discovers the PR by the rendered branch
through the GitHub pulls list endpoint.

Multi-package jobs (payload carries a ``packages`` list, one entry per
package flagged by the same alert) run the same per-package agent analysis
sequentially through the backend, but the agent is told not to touch
GitHub.  The orchestrator then splits the verified per-package results:

- every verified FP package is aggregated into ONE PR via the harness
  ``fp_agent_pr`` multi-package render (one suppression file and one
  findings-table section per package), opened by :mod:`pr_open` and
  validated by the same PR backstop as single-package jobs;
- every verified TP package gets the confirmed-IOC flow for that package
  only: the ``trustsight.confirmed-ioc`` alert (ntfy + signed feed) and an
  IOC register PR, both driven by the harness renders;
- uncertain packages contribute nothing and are recorded in the outcome
  reason (the job still resolves through the FP/TP packages).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from . import runner, special_alert
from .pr_backstop import check_pr, harness_render_pr
from .pr_open import open_pr
from .prompt import build_prompt
from .queue import JobQueue, TransitionError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineOutcome:
    status: str  # mirrors JobQueue statuses
    reason: str | None = None
    pr_url: str | None = None


@dataclass(frozen=True)
class _MultiResults:
    fp: list = field(default_factory=list)   # verified FP verify_results
    tp: list = field(default_factory=list)   # verified TP verify_results
    uncertain: list = field(default_factory=list)  # package names


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
    pr_open: object = open_pr,
    render: object = harness_render_pr,
) -> PipelineOutcome:
    """Run one claimed job end to end, transitioning the queue record."""

    cli = getattr(settings, "harness_cli", "harness")
    timeout = getattr(settings, "harness_timeout_seconds", 900)

    try:
        queue.transition(job_id, "running")
    except TransitionError:
        if queue.get(job_id).status != "running":
            return PipelineOutcome(status="failed", reason="job not claimable")

    if isinstance(payload.get("packages"), list):
        return _process_multi_job(
            job_id=job_id,
            payload=payload,
            settings=settings,
            queue=queue,
            backend=backend,
            verify=verify,
            backstop=backstop,
            send=send,
            http_client=http_client,
            pr_open=pr_open,
            render=render,
            cli=cli,
            timeout=timeout,
        )

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
        check = backstop(
            pr_url=pr_url,
            verify_result=result,
            token=getattr(settings, "github_token", None),
            client=http_client,
            cli=cli,
            discover_branch=pr_url is None,
            pr_owner=getattr(settings, "github_owner", None),
        )
        if not check.ok:
            reason = f"PR backstop: {check.reason}"
            queue.transition(job_id, "failed", error=reason)
            return PipelineOutcome(status="failed", reason=reason, pr_url=pr_url)
        queue.transition(job_id, "pr_opened", pr_url=check.pr_url or pr_url)
        return PipelineOutcome(
            status="pr_opened", pr_url=check.pr_url or pr_url
        )

    reason = f"unsupported verified kind: {kind!r}"
    queue.transition(job_id, "failed", error=reason)
    return PipelineOutcome(status="failed", reason=reason)


def _process_multi_job(
    *,
    job_id: str,
    payload: dict,
    settings: object,
    queue: JobQueue,
    backend: runner.RunnerBackend,
    verify: object,
    backstop: object,
    send: object,
    http_client: object | None,
    pr_open: object,
    render: object,
    cli: str,
    timeout: int,
) -> PipelineOutcome:
    """One job covering every package flagged by the same alert."""

    job_root = getattr(settings, "job_root", "/job")
    token = getattr(settings, "github_token", None)
    owner = getattr(settings, "github_owner", None)
    entries = [e for e in payload.get("packages", []) if isinstance(e, dict)]
    if not entries:
        queue.transition(job_id, "failed", error="multi job has no packages")
        return PipelineOutcome(status="failed", reason="multi job has no packages")

    results = _MultiResults()
    for entry in entries:
        package = entry.get("package", "?")
        prompt = build_prompt(entry, open_pr=False)
        outcome = runner.run_job(
            job_id=job_id,
            prompt=prompt,
            job_root=job_root,
            backend=backend,
            cli=cli,
            timeout=timeout,
            verify=verify,
        )
        if outcome.outcome == "failed":
            reason = f"package {package}: {outcome.reason or 'agent run failed'}"
            queue.transition(job_id, "failed", error=reason[:512])
            return PipelineOutcome(status="failed", reason=reason)
        if outcome.outcome == "needs_review":
            results.uncertain.append(package)
            continue
        verdict = outcome.verdict or {}
        result = outcome.verify_result or {}
        kind = result.get("kind") or verdict.get("verdict")
        if kind == "FP":
            results.fp.append(result)
        elif kind == "TP":
            results.tp.append(result)
        else:
            results.uncertain.append(package)

    queue.transition(job_id, "verified")

    summary = (f"{len(results.fp)} FP, {len(results.tp)} TP,"
               f" {len(results.uncertain)} uncertain")
    if results.uncertain:
        summary += f" (needs_review: {', '.join(results.uncertain)})"

    # TP packages first: the confirmed-IOC flow for those packages only.  If
    # anything here fails, no FP PR exists yet, so a retry cannot duplicate
    # one.
    for result in results.tp:
        package = result.get("package", "?")
        try:
            alert = special_alert.harness_alert(result, cli=cli, timeout=timeout)
            delivered = send(alert, settings, client=http_client)
        except Exception as exc:
            delivered = special_alert.AlertResult(reason=str(exc))
        if not (getattr(delivered, "ntfy", False)
                or getattr(delivered, "feed", False)):
            reason = (f"package {package}: alert delivery failed:"
                      f" {getattr(delivered, 'reason', 'unknown')}")
            queue.transition(job_id, "failed", error=reason[:512])
            return PipelineOutcome(status="failed", reason=reason)
        try:
            ioc_render = render(result, target_repo="trustsight", cli=cli)
            pr_open(rendered=ioc_render, token=token, owner=owner,
                 client=http_client)
        except Exception as exc:
            reason = f"package {package}: IOC PR open failed: {exc}"
            queue.transition(job_id, "failed", error=reason[:512])
            return PipelineOutcome(status="failed", reason=reason)

    pr_url = None
    if results.fp:
        aggregate = {"kind": "FP", "verified": True, "packages": results.fp}
        try:
            fp_render = render(aggregate, target_repo="trustsight", cli=cli)
            pr_url = pr_open(rendered=fp_render, token=token, owner=owner,
                          client=http_client)
        except Exception as exc:
            reason = f"aggregate FP PR open failed: {exc}"
            queue.transition(job_id, "failed", error=reason[:512])
            return PipelineOutcome(status="failed", reason=reason)
        check = backstop(
            pr_url=pr_url,
            verify_result=aggregate,
            token=token,
            client=http_client,
            cli=cli,
            discover_branch=False,
            pr_owner=owner,
        )
        if not check.ok:
            reason = f"PR backstop: {check.reason}"
            queue.transition(job_id, "failed", error=reason[:512])
            return PipelineOutcome(status="failed", reason=reason, pr_url=pr_url)
        queue.transition(job_id, "pr_opened", pr_url=pr_url)
        return PipelineOutcome(status="pr_opened", pr_url=pr_url,
                               reason=summary)

    if results.tp:
        queue.transition(job_id, "alert_sent")
        return PipelineOutcome(status="alert_sent", reason=summary)

    queue.transition(job_id, "needs_review")
    return PipelineOutcome(status="needs_review", reason=summary)
