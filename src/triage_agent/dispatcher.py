"""Poll the TrustSight feed for ``trustsight.alerts`` events and enqueue jobs.

The feed sink (trustsight-feed worker) stores each watcher notification as a
row whose payload carries ``alerts`` and ``over_threshold`` blocks. We query
``GET {feed_url}/api/feed?event=trustsight.alerts`` and dedupe on the sha256
of the canonical JSON of those two blocks, so re-delivered cycles do not
double-enqueue while a genuinely new cycle does.

``poll_once`` is a pure, testable generator; ``run_forever`` is the infinite
loop around it and must never crash on network or parse errors.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .queue import JobQueue

log = logging.getLogger(__name__)

EVENT_NAME = "trustsight.alerts"
DEFAULT_LIMIT = 50


class HttpClient(Protocol):
    """The slice of httpx.Client the dispatcher uses; tests fake this."""

    def get(self, url: str, **kwargs: object) -> httpx.Response: ...


@dataclass
class Deduper:
    """Hashes of alert blocks already enqueued, per process run."""

    seen: set[str] = field(default_factory=set)

    def mark_and_is_new(self, digest: str) -> bool:
        if digest in self.seen:
            return False
        self.seen.add(digest)
        return True


def event_digest(payload: dict) -> str:
    """Dedupe key: canonical JSON of the (alerts, over_threshold) blocks."""

    block = {
        "alerts": payload.get("alerts", []),
        "over_threshold": payload.get("over_threshold", []),
    }
    canonical = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def job_payload(entry: dict) -> dict:
    """Canonical payload for one (package, version transition) job."""

    return {
        "package": entry["package"],
        "old_version": entry.get("old_version"),
        "new_version": entry.get("new_version"),
        "aur_url": entry.get("aur_url"),
        "rules": entry.get("rules", []),
    }


def rows_from_feed(body: object) -> list[dict]:
    """Extract notification payloads from the feed API response body.

    Accepts either a bare list of rows or an object with a ``rows``/``items``
    list. Each row's ``payload`` (parsed JSON string or dict) is returned.
    """

    if isinstance(body, dict):
        rows = body.get("rows") or body.get("items") or []
    elif isinstance(body, list):
        rows = body
    else:
        rows = []
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("payload", row)
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                log.warning("skipping row %s: unparseable payload", row.get("id"))
                continue
        if isinstance(payload, dict) and payload.get("event") == EVENT_NAME:
            out.append(payload)
    return out


def fetch_events(
    client: HttpClient,
    feed_url: str,
    *,
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
) -> list[dict]:
    """One HTTP GET, parsed into trustsight.alerts payloads. Raises on error."""

    base = feed_url.rstrip("/")
    resp = client.get(
        f"{base}/api/feed",
        params={"event": EVENT_NAME, "limit": limit},
        timeout=timeout,
    )
    resp.raise_for_status()
    return rows_from_feed(resp.json())


def poll_once(
    client: HttpClient,
    feed_url: str,
    queue: JobQueue,
    deduper: Deduper,
    *,
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
) -> Iterator[tuple[str, str]]:
    """Fetch once and enqueue new jobs. Yields (job_id, package) per new job."""

    try:
        payloads = fetch_events(client, feed_url, limit=limit, timeout=timeout)
    except Exception:
        log.exception("feed poll failed; will retry next cycle")
        return
    for payload in payloads:
        digest = event_digest(payload)
        if not deduper.mark_and_is_new(digest):
            continue
        for entry in payload.get("over_threshold", []):
            if not isinstance(entry, dict) or "package" not in entry:
                log.warning("over_threshold entry missing package: %r", entry)
                continue
            payload_for_job = job_payload(entry)
            kind = "ioc" if entry.get("ioc_matches") else "triage"
            job, created = queue.enqueue(
                payload_for_job, package=entry["package"], kind=kind
            )
            if created:
                log.info("enqueued %s job %s for %s", kind, job.id, job.package)
                yield job.id, job.package


def run_forever(
    settings: object,
    queue: JobQueue,
    *,
    deduper: Deduper | None = None,
    sleep: object = time.sleep,
) -> None:
    """Infinite poll loop. Network failures are logged, never raised."""

    deduper = deduper or Deduper()
    interval = getattr(settings, "poll_interval_seconds", 120)
    feed_url = getattr(settings, "feed_url", "")
    with httpx.Client() as client:
        while True:
            for _job_id, _pkg in poll_once(client, feed_url, queue, deduper):
                pass
            sleep(interval)
