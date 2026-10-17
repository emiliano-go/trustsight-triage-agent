"""Pipeline composition: FP, TP, needs_review, verify failure, no-PR paths."""

from __future__ import annotations

import pytest

from triage_agent import pipeline
from triage_agent.config import Settings
from triage_agent.queue import JobQueue
from triage_agent.runner import LocalStubBackend

PR_URL = "https://github.com/acme/trustsight/pull/42"


def _settings(tmp_path) -> Settings:
    return Settings(job_root=str(tmp_path / "jobs"))


def _enqueue(queue, alerts_event):
    entry = alerts_event["over_threshold"][0]
    payload = {
        "package": entry["package"],
        "old_version": entry.get("old_version"),
        "new_version": entry.get("new_version"),
        "aur_url": entry.get("aur_url"),
        "rules": entry.get("rules", []),
    }
    job, _ = queue.enqueue(payload, package=entry["package"])
    return job, payload


@pytest.fixture()
def queue(tmp_path):
    with JobQueue(tmp_path / "triage.sqlite3") as q:
        yield q


def _verify_fp(verdict, **kwargs):
    return {"verified": True, "kind": "FP", "package": verdict["package"]}


def _verify_tp(verdict, **kwargs):
    return {"verified": True, "kind": "TP", "package": verdict["package"]}


class _BackstopResult:
    def __init__(self, ok, reason):
        self.ok = ok
        self.reason = reason


def test_fp_happy_path(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)
    backend = LocalStubBackend()
    backend.last_pr_url = PR_URL
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
        verify=_verify_fp,
        backstop=lambda **k: _BackstopResult(True, None),
    )
    assert outcome.status == "pr_opened"
    assert outcome.pr_url == PR_URL
    stored = queue.get(job.id)
    assert stored.status == "pr_opened"
    assert stored.pr_url == PR_URL
    assert backend.calls[0]["prompt"]


def test_tp_happy_path_sends_alert(tmp_path, queue, alerts_event, monkeypatch):
    job, payload = _enqueue(queue, alerts_event)
    backend = LocalStubBackend(
        {"schema_version": 1, "package": "hello-aur", "verdict": "TP",
         "confidence": "high", "rationale": "confirmed", "evidence": {},
         "proposed_changes": {}}
    )
    sent: list[dict] = []

    def fake_send(alert, settings, **kwargs):
        sent.append(alert)
        return pipeline.special_alert.AlertResult(ntfy=True)

    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
        verify=_verify_tp,
        backstop=lambda **k: pytest.fail("backstop must not run for TP"),
        send=fake_send,
    )
    assert outcome.status == "alert_sent"
    assert queue.get(job.id).status == "alert_sent"
    assert sent[0]["kind"] == "TP"


def test_needs_review_short_circuits(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)
    backend = LocalStubBackend(
        {"schema_version": 1, "package": "hello-aur", "verdict": "uncertain",
         "confidence": "medium", "rationale": "?", "evidence": {},
         "proposed_changes": {}}
    )
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
    )
    assert outcome.status == "needs_review"
    assert queue.get(job.id).status == "needs_review"


def test_verify_failure_fails_job(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)

    def boom(verdict, **kwargs):
        raise RuntimeError("harness unreachable")

    backend = LocalStubBackend()
    backend.last_pr_url = PR_URL
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
        verify=boom,
    )
    assert outcome.status == "failed"
    assert "harness unreachable" in outcome.reason
    assert queue.get(job.id).status == "failed"
    assert queue.get(job.id).error


def test_no_pr_fails_job(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=LocalStubBackend(),
        verify=_verify_fp,
    )
    assert outcome.status == "failed"
    assert "no PR found" in outcome.reason


def test_backstop_mismatch_fails_job(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)
    backend = LocalStubBackend()
    backend.last_pr_url = PR_URL
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
        verify=_verify_fp,
        backstop=lambda **k: _BackstopResult(False, "title mismatch"),
    )
    assert outcome.status == "failed"
    assert "title mismatch" in outcome.reason


def test_alert_delivery_failure_fails_job(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)
    backend = LocalStubBackend(
        {"schema_version": 1, "package": "hello-aur", "verdict": "TP",
         "confidence": "high", "rationale": "confirmed", "evidence": {},
         "proposed_changes": {}}
    )
    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=backend,
        verify=_verify_tp,
        send=lambda *a, **k: pipeline.special_alert.AlertResult(reason="sinks down"),
    )
    assert outcome.status == "failed"
    assert "sinks down" in outcome.reason


def test_backend_failure_fails_job(tmp_path, queue, alerts_event):
    job, payload = _enqueue(queue, alerts_event)

    class BrokenBackend:
        def run(self, *, prompt, job_id, job_root):
            raise RuntimeError("container exploded")

    outcome = pipeline.process_job(
        job_id=job.id,
        payload=payload,
        settings=_settings(tmp_path),
        queue=queue,
        backend=BrokenBackend(),
    )
    assert outcome.status == "failed"
    assert "container exploded" in outcome.reason
