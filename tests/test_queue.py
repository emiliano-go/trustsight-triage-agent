import pytest

from triage_agent.queue import (
    JobQueue,
    QueueError,
    TransitionError,
    content_hash,
    safe_job_path,
    write_job_file,
)


@pytest.fixture()
def queue(tmp_path):
    with JobQueue(tmp_path / "jobs.sqlite3") as q:
        yield q


def test_enqueue_and_dedupe(queue):
    payload = {"package": "a", "new_version": "1-1"}
    job, created = queue.enqueue(payload, package="a")
    assert created
    job2, created2 = queue.enqueue(payload, package="a")
    assert not created2
    assert job2.id == job.id
    assert job.status == "queued"


def test_content_hash_is_order_independent():
    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})


def test_happy_path_transitions(queue):
    job, _ = queue.enqueue({"package": "a"}, package="a")
    job = queue.transition(job.id, "running")
    job = queue.transition(job.id, "verified", verdict_path="/job/x/verdict.json")
    job = queue.transition(job.id, "pr_opened", pr_url="https://github.com/x/pull/1")
    assert job.pr_url == "https://github.com/x/pull/1"
    assert job.verdict_path == "/job/x/verdict.json"


def test_alert_path(queue):
    job, _ = queue.enqueue({"package": "a"}, package="a", kind="ioc")
    queue.transition(job.id, "running")
    job = queue.transition(job.id, "verified")
    job = queue.transition(job.id, "alert_sent")
    assert job.kind == "ioc"


def test_illegal_transitions_rejected(queue):
    job, _ = queue.enqueue({"package": "a"}, package="a")
    with pytest.raises(TransitionError):
        queue.transition(job.id, "verified")
    queue.transition(job.id, "running")
    job = queue.transition(job.id, "failed", error="boom")
    assert job.error == "boom"
    with pytest.raises(TransitionError):
        queue.transition(job.id, "running")


def test_claim_next_atomic(queue):
    queue.enqueue({"package": "a"}, package="a")
    queue.enqueue({"package": "b"}, package="b")
    first = queue.claim_next()
    second = queue.claim_next()
    assert first.package == "a"
    assert second.package == "b"
    assert queue.claim_next() is None


def test_missing_job_raises(queue):
    with pytest.raises(QueueError):
        queue.get("nope")


def test_safe_path_rejects_traversal_and_symlink(tmp_path):
    with pytest.raises(QueueError):
        safe_job_path(tmp_path, "../escape", "verdict.json")
    with pytest.raises(QueueError):
        safe_job_path(tmp_path, "job1", "sub/verdict.json")
    link = tmp_path / "link"
    link.symlink_to("/tmp")
    with pytest.raises(QueueError):
        safe_job_path(link, "job1", "verdict.json")


def test_write_job_file_refuses_symlink_target(tmp_path):
    job_id = "abc"
    real = write_job_file(tmp_path, job_id, "verdict.json", b"{}")
    assert real.read_bytes() == b"{}"
    real.unlink()
    real.symlink_to("/etc/passwd")  # final path is now a symlink
    with pytest.raises(QueueError):
        write_job_file(tmp_path, job_id, "verdict.json", b"x")
