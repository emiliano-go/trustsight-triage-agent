"""Recovery paths: persistent event dedupe and stale-job requeue."""

import time

from triage_agent.dispatcher import Deduper, poll_once
from triage_agent.queue import JobQueue

from .conftest import FakeHttpClient


def feed_rows(payloads):
    return [{"id": str(i), "payload": p} for i, p in enumerate(payloads)]


def test_seen_events_survive_restart(tmp_path, alerts_event):
    """A new queue instance over the same DB file must not re-enqueue."""
    db = tmp_path / "jobs.sqlite3"
    client = FakeHttpClient(feed_rows([alerts_event]))
    with JobQueue(db) as queue:
        jobs = list(
            poll_once(client, "https://feed.example.org", queue, Deduper())
        )
        assert len(jobs) == 1
    # Dispatcher restart: fresh in-memory deduper, fresh queue instance.
    with JobQueue(db) as queue:
        second = list(
            poll_once(client, "https://feed.example.org", queue, Deduper())
        )
        assert second == []
        assert len(queue.by_status("queued")) == 1


def test_seen_events_marked_once_per_event(tmp_path, alerts_event, ioc_event):
    db = tmp_path / "jobs.sqlite3"
    with JobQueue(db) as queue:
        deduper = Deduper()
        c1 = FakeHttpClient(feed_rows([alerts_event]))
        assert len(list(poll_once(c1, "https://feed.example.org", queue,
                                  deduper))) == 1
        c2 = FakeHttpClient(feed_rows([alerts_event, ioc_event]))
        jobs = list(poll_once(c2, "https://feed.example.org", queue, deduper))
        assert len(jobs) == 1  # only the new IOC cycle enqueues


def test_requeue_stale_running_jobs(tmp_path):
    db = tmp_path / "jobs.sqlite3"
    with JobQueue(db) as queue:
        job, _ = queue.enqueue({"package": "a"}, package="a")
        queue.transition(job.id, "running")
        # Fresh enough: not requeued.
        assert queue.requeue_stale(3600) == 0
        assert queue.get(job.id).status == "running"
        # Simulate a crash long ago.
        old = time.time() - 7200
        queue._conn.execute(
            "UPDATE jobs SET updated_at = ? WHERE id = ?", (old, job.id)
        )
        assert queue.requeue_stale(3600) == 1
        assert queue.get(job.id).status == "queued"
        # The requeued job is claimable again.
        claimed = queue.claim_next()
        assert claimed is not None and claimed.id == job.id


def test_requeue_stale_leaves_other_statuses(tmp_path):
    db = tmp_path / "jobs.sqlite3"
    with JobQueue(db) as queue:
        queued_job, _ = queue.enqueue({"package": "a"}, package="a")
        done_job, _ = queue.enqueue({"package": "b"}, package="b")
        queue.transition(done_job.id, "running")
        queue.transition(done_job.id, "verified")
        old = time.time() - 7200
        queue._conn.execute(
            "UPDATE jobs SET updated_at = ? WHERE status != 'verified'",
            (old,),
        )
        assert queue.requeue_stale(3600) == 0
        assert queue.get(queued_job.id).status == "queued"
        assert queue.get(done_job.id).status == "verified"


def test_claim_next_returns_none_when_claim_raced(tmp_path):
    """If the UPDATE loses the CAS, claim_next must not hand out the job."""

    class RacingConn:
        """Proxy that lets a concurrent claim win the guarded UPDATE."""

        def __init__(self, conn):
            object.__setattr__(self, "_conn", conn)

        def __getattr__(self, name):
            return getattr(object.__getattribute__(self, "_conn"), name)

        def __setattr__(self, name, value):
            setattr(object.__getattribute__(self, "_conn"), name, value)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def execute(self, sql, params=()):
            conn = object.__getattribute__(self, "_conn")
            if "UPDATE jobs SET status = 'running'" in sql:
                conn.execute(
                    "UPDATE jobs SET status = 'running', updated_at = ?"
                    " WHERE id = ?",
                    (time.time(), params[1]),
                )
            return conn.execute(sql, params)

    db = tmp_path / "jobs.sqlite3"
    with JobQueue(db) as queue:
        queue.enqueue({"package": "a"}, package="a")
        queue._conn = RacingConn(queue._conn)
        assert queue.claim_next() is None
        queue._conn = queue._conn._conn
        # The concurrent claimer owns the job; it is not queued anymore.
        assert queue.by_status("queued") == []
        assert queue.by_status("running")[0].package == "a"
