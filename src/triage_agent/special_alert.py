"""Transport-only alert delivery for confirmed IOCs.

Posts the confirmed-ioc alert envelope (from ``harness fp_agent_alert``)
to the ntfy webhook and, when a feed key is configured, to the signed feed
sink.  The feed signing mirrors trustsight ``notify.py`` exactly: Ed25519
over the material ``webhook_id.timestamp.body``, key as base64 PKCS#8 (DER).

Nothing here raises: a failed notification must never fail the job loop,
so :func:`send_alert` always returns a structured result.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 64 * 1024
USER_AGENT = "trustsight-triage-agent/0.1"

_PRIORITY_HEADERS = {
    "low": {"Priority": "2", "Tags": "hourglass"},
    "default": {"Tags": "eye"},
}


@dataclass(frozen=True)
class AlertResult:
    ntfy: bool = False
    feed: bool = False
    reason: str | None = None


def harness_alert(
    result: dict,
    *,
    cli: str = "harness",
    timeout: int = 900,
) -> dict:
    """Render the confirmed-ioc envelope via `harness fp_agent_alert`.

    The verified TP result travels as a temp file, matching
    ``runner.harness_verify``.  Raises RuntimeError when the CLI fails.
    """

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", encoding="utf-8", delete=False
    ) as handle:
        json.dump(result, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [cli, "fp_agent_alert", "--result", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        raise RuntimeError(
            f"harness fp_agent_alert exited {proc.returncode}:"
            f" {proc.stderr.strip()[:512]}"
        )
    alert = json.loads(proc.stdout)
    if isinstance(alert, dict) and alert.get("error"):
        raise RuntimeError(f"harness fp_agent_alert: {alert['error']}")
    return alert


def sign_feed_body(key_b64: str, key_id: str, body: bytes) -> dict[str, str]:
    """The webhook-id/timestamp/signature headers for *body*.

    Same construction as trustsight.notify._sign_feed: the id is
    deterministic from (timestamp, body) so a retried POST dedupes.
    """

    from cryptography.hazmat.primitives.serialization import load_der_private_key

    timestamp = int(time.time())
    webhook_id = hashlib.sha256(f"{timestamp}.".encode() + body).hexdigest()
    key = load_der_private_key(base64.b64decode(key_b64), password=None)
    signature = key.sign(f"{webhook_id}.{timestamp}.".encode() + body)
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": str(timestamp),
        "webhook-key-id": key_id,
        "webhook-signature": "v1=" + base64.b64encode(signature).decode(),
    }


def _post(client: httpx.Client, url: str, **kwargs: object) -> None:
    resp = client.post(url, timeout=TIMEOUT_SECONDS, **kwargs)
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise RuntimeError("response exceeds size cap")
    resp.raise_for_status()


def send_alert(
    alert: dict,
    settings: object,
    *,
    client: httpx.Client | None = None,
) -> AlertResult:
    """POST *alert* to ntfy and the signed feed. Never raises."""

    ntfy_url = getattr(settings, "ntfy_webhook", None)
    feed_url = getattr(settings, "feed_url", None)
    feed_key = getattr(settings, "feed_key", None)
    key_id = getattr(settings, "feed_key_id", "") or ""

    ntfy_ok = False
    feed_ok = False
    try:
        with client or httpx.Client() as http:
            if ntfy_url:
                headers = {"Content-Type": "application/json",
                           "User-Agent": USER_AGENT}
                if alert.get("title"):
                    headers["Title"] = alert["title"]
                headers.update(
                    _PRIORITY_HEADERS.get(alert.get("priority", "default"), {})
                )
                try:
                    _post(http, ntfy_url, content=json.dumps(alert).encode(),
                          headers=headers)
                    ntfy_ok = True
                except Exception as exc:
                    log.warning("ntfy alert POST failed: %s", exc)
            if feed_url and feed_key:
                body = json.dumps(alert).encode()
                headers = {"Content-Type": "application/json",
                           "User-Agent": USER_AGENT}
                try:
                    headers.update(sign_feed_body(feed_key, key_id, body))
                    _post(http, feed_url, content=body, headers=headers)
                    feed_ok = True
                except Exception as exc:
                    log.warning("feed alert POST failed: %s", exc)
            elif not feed_key:
                log.info("no TRUSTSIGHT_FEED_KEY; skipping signed feed POST")
    except Exception as exc:
        log.warning("alert delivery failed: %s", exc)
    reason = None if (ntfy_ok or feed_ok) else "no sink accepted the alert"
    return AlertResult(ntfy=ntfy_ok, feed=feed_ok, reason=reason)
