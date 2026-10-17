"""Worker loop: claiming, payload restore, crash isolation, signals."""

import os
import signal
import sqlite3

import pytest

from triage_agent.config import Settings
from triage_agent.queue import JobQueue
from triage_agent.worker import Worker


@pytest.fixture()
def queue(tmp_path):
    with JobQueue(tmp_path / "jobs.sqlite3") as q:
        yield q


def make_worker(queue, tmp_path, backend=None, process=None, idles=3,
                **settings_over):
    settings = Settings(job_root=str(tmp_path / "jobs"), **settings_over)
    sleeps: list[float] = []

    def sleeper(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= idles:
            worker.stop()

    worker = Worker(
        settings,
        queue,
        backend=backend or object(),
        process=process or (lambda **k: None),
        sleeper=sleeper,
        poll_interval=7,
    )
    return worker, sleeps


def test_payload_round_trips_through_queue(queue):
    payload = {"package": "a", "new_version": "1-1", "rules": ["r"]}
    job, _ = queue.enqueue(payload, package="a")
    assert job.payload_dict() == payload


def test_processes_queued_job_to_completion(queue, tmp_path, alerts_event):
    calls: list[dict] = []

    def process(**kwargs):
        calls.append(kwargs)
        queue.transition(kwargs["job_id"], "verified")

    worker, _ = make_worker(queue, tmp_path, process=process)
    entry = alerts_event["over_threshold"][0]
    payload = {"package": entry["package"], "rules": entry.get("rules", [])}
    job, _ = queue.enqueue(payload, package=entry["package"])
    worker.run_forever()
    assert [c["job_id"] for c in calls] == [job.id]
    assert calls[0]["payload"] == payload
    assert calls[0]["backend"] is worker._backend
    assert queue.get(job.id).status == "verified"


def test_idle_poll_then_stop(queue, tmp_path):
    worker, sleeps = make_worker(queue, tmp_path, idles=3)
    worker.run_forever()
    assert sleeps == [7, 7, 7]


def test_requeues_stale_running_job_on_startup(queue, tmp_path):
    job, _ = queue.enqueue({"package": "a"}, package="a")
    queue.transition(job.id, "running")
    old = job.updated_at - 7200
    queue._conn.execute(
        "UPDATE jobs SET updated_at = ? WHERE id = ?", (old, job.id)
    )
    worker, _ = make_worker(queue, tmp_path, idles=1)
    worker.run_forever()
    assert queue.get(job.id).status == "running"  # requeued, then claimed
    assert queue.get(job.id).updated_at > old


def test_job_without_payload_fails_closed(queue, tmp_path):
    """A pre-migration row (no payload column value) must not wedge the loop."""
    job, _ = queue.enqueue({"package": "a"}, package="a")
    queue._conn.execute("UPDATE jobs SET payload = NULL WHERE id = ?",
                        (job.id,))
    worker, _ = make_worker(queue, tmp_path, idles=1)
    worker.run_forever()
    assert queue.get(job.id).status == "failed"
    assert "payload" in queue.get(job.id).error


def test_process_crash_fails_job_and_loop_survives(queue, tmp_path):
    first, _ = queue.enqueue({"package": "a"}, package="a")
    second, _ = queue.enqueue({"package": "b"}, package="b")
    seen: list[str] = []

    def process(**kwargs):
        seen.append(kwargs["job_id"])
        if kwargs["job_id"] == first.id:
            raise RuntimeError("pipeline bug")
        queue.transition(kwargs["job_id"], "verified")

    worker, _ = make_worker(queue, tmp_path, process=process, idles=1)
    worker.run_forever()
    assert seen == [first.id, second.id]
    assert queue.get(first.id).status == "failed"
    assert queue.get(second.id).status == "verified"


def test_sigterm_sets_stop_flag(queue, tmp_path):
    worker, _ = make_worker(queue, tmp_path)
    old_term = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    old_int = signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        worker.install_signal_handlers()
        os.kill(os.getpid(), signal.SIGTERM)
        assert worker._stop is True
        worker._stop = False
        os.kill(os.getpid(), signal.SIGINT)
        assert worker._stop is True
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def test_payload_column_migrated_into_existing_db(tmp_path):
    """A first-schema-version DB file gains the column without data loss."""
    db = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE jobs (id TEXT PRIMARY KEY, content_hash TEXT NOT NULL"
        " UNIQUE, package TEXT NOT NULL, status TEXT NOT NULL,"
        " kind TEXT NOT NULL DEFAULT 'triage', verdict_path TEXT, pr_url"
        " TEXT, error TEXT, created_at REAL NOT NULL, updated_at REAL NOT"
        " NULL)"
    )
    conn.execute(
        "INSERT INTO jobs (id, content_hash, package, status, created_at,"
        " updated_at) VALUES ('j1', 'h1', 'a', 'queued', 1.0, 1.0)"
    )
    conn.commit()
    conn.close()
    with JobQueue(db) as queue:
        job = queue.get("j1")
        assert job.payload is None
        assert job.payload_dict() is None
        job2, created = queue.enqueue({"package": "b"}, package="b")
        assert created
        assert job2.payload_dict() == {"package": "b"}
