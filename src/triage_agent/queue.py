"""SQLite job queue with strict status transitions and safe file writes.

Job lifecycle::

    queued -> running -> verified -> pr_opened
                        -> failed   (verified -> failed: backstop/alert failure)
                 verified (TP) -> alert_sent

``ioc`` kind jobs short-circuit: they are enqueued already resolved for the
alert path and are never handed to the agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL UNIQUE,
    package TEXT NOT NULL,
    status TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'triage',
    verdict_path TEXT,
    pr_url TEXT,
    error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""

STATUSES = (
    "queued",
    "running",
    "verified",
    "failed",
    "pr_opened",
    "alert_sent",
    "needs_review",
)

#: status -> statuses it may move to
_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"running"}),
    "running": frozenset({"verified", "failed", "needs_review"}),
    "verified": frozenset({"pr_opened", "alert_sent", "needs_review", "failed"}),
    "failed": frozenset(),
    "pr_opened": frozenset(),
    "alert_sent": frozenset(),
    "needs_review": frozenset({"running"}),
}


class QueueError(RuntimeError):
    pass


class TransitionError(QueueError):
    pass


def content_hash(payload: dict) -> str:
    """Stable dedupe key for a job payload."""

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def safe_job_path(job_root: str | Path, job_id: str, name: str) -> Path:
    """Resolve a path under job_root, refusing symlinks and traversal.

    Every existing parent component must be a real directory (no symlinks),
    and the final file is opened with O_NOFOLLOW by :func:`write_job_file`.
    """

    root = Path(os.path.abspath(job_root))
    if os.path.islink(root):
        raise QueueError(f"job root is a symlink: {root}")
    if not name or os.path.basename(name) != name:
        raise QueueError(f"unsafe file name: {name!r}")
    if not job_id or os.path.basename(job_id) != job_id:
        raise QueueError(f"unsafe job id: {job_id!r}")
    path = root / job_id / name
    resolved_root = os.path.realpath(os.path.abspath(root))
    resolved_parent = os.path.realpath(os.path.abspath(path.parent))
    if (
        resolved_parent != resolved_root
        and not resolved_parent.startswith(resolved_root + os.sep)
    ) or os.path.islink(path.parent) or os.path.islink(path):
        raise QueueError(f"path escapes job root or uses symlinks: {path}")
    return path


def write_job_file(job_root: str | Path, job_id: str, name: str, data: bytes) -> Path:
    """Write a file under job_root with symlink resistance (O_NOFOLLOW)."""

    path = safe_job_path(job_root, job_id, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


@dataclass(frozen=True)
class Job:
    id: str
    content_hash: str
    package: str
    status: str
    kind: str
    verdict_path: str | None
    pr_url: str | None
    error: str | None
    created_at: float
    updated_at: float


def _row_to_job(row: sqlite3.Row) -> Job:
    return Job(
        id=row["id"],
        content_hash=row["content_hash"],
        package=row["package"],
        status=row["status"],
        kind=row["kind"],
        verdict_path=row["verdict_path"],
        pr_url=row["pr_url"],
        error=row["error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class JobQueue:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> JobQueue:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _transition_ok(self, old: str, new: str) -> bool:
        return new in _TRANSITIONS.get(old, frozenset())

    def enqueue(
        self,
        payload: dict,
        *,
        package: str,
        kind: str = "triage",
    ) -> tuple[Job, bool]:
        """Insert a queued job. Returns (job, created); dupes return existing."""

        digest = content_hash(payload)
        now = time.time()
        job_id = uuid.uuid4().hex
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO jobs (id, content_hash, package, status, kind,"
                    " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                    (job_id, digest, package, "queued", kind, now, now),
                )
        except sqlite3.IntegrityError:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE content_hash = ?", (digest,)
            ).fetchone()
            return _row_to_job(row), False
        row = self._conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return _row_to_job(row), True

    def transition(
        self,
        job_id: str,
        new_status: str,
        *,
        verdict_path: str | None = None,
        pr_url: str | None = None,
        error: str | None = None,
    ) -> Job:
        """Move a job to new_status inside one transaction; CAS on status."""

        if new_status not in STATUSES:
            raise TransitionError(f"unknown status: {new_status}")
        with self._conn:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise QueueError(f"no such job: {job_id}")
            old = row["status"]
            if not self._transition_ok(old, new_status):
                raise TransitionError(f"illegal transition {old} -> {new_status}")
            self._conn.execute(
                "UPDATE jobs SET status = ?, verdict_path = COALESCE(?,"
                " verdict_path), pr_url = COALESCE(?, pr_url),"
                " error = COALESCE(?, error), updated_at = ? WHERE id = ?",
                (
                    new_status,
                    verdict_path,
                    pr_url,
                    error,
                    time.time(),
                    job_id,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return _row_to_job(row)

    def claim_next(self) -> Job | None:
        """Atomically mark the oldest queued job running. Lock-friendly."""

        with self._conn:
            row = self._conn.execute(
                "SELECT id FROM jobs WHERE status = 'queued'"
                " ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            job_id = row["id"]
            self._conn.execute(
                "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ?"
                " AND status = 'queued'",
                (time.time(), job_id),
            )
        return self.get(job_id)

    def get(self, job_id: str) -> Job:
        row = self._conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise QueueError(f"no such job: {job_id}")
        return _row_to_job(row)

    def by_status(self, status: str) -> list[Job]:
        rows = self._conn.execute(
            "SELECT * FROM jobs WHERE status = ? ORDER BY created_at", (status,)
        ).fetchall()
        return [_row_to_job(r) for r in rows]
