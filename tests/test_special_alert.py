"""special_alert delivery: ntfy POST, signed feed POST, and the skip path."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization

from triage_agent import special_alert
from triage_agent.config import Settings

ALERT = {"event": "trustsight.confirmed-ioc", "priority": "default",
         "title": "Confirmed IOC: hello-aur", "package": "hello-aur"}


class FakePostResponse:
    status_code = 200
    content = b"ok"

    def raise_for_status(self) -> None:
        return None


class FakePostClient:
    """Duck-typed httpx.Client: supports context manager and post()."""

    def __init__(self, fail_urls: set[str] | None = None):
        self.posts: list[dict] = []
        self._fail = fail_urls or set()

    def __enter__(self) -> FakePostClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, **kwargs) -> FakePostResponse:
        self.posts.append({"url": url, **kwargs})
        if url in self._fail:
            raise RuntimeError("sink down")
        return FakePostResponse()


def _feed_key() -> tuple[str, object]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    key = Ed25519PrivateKey.generate()
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(der).decode(), key.public_key()


def test_ntfy_posted_with_headers(tmp_path, monkeypatch):
    client = FakePostClient()
    settings = Settings(
        ntfy_webhook="https://ntfy.example/alerts",
        feed_url="https://feed.example/api/ingest",
    )
    result = special_alert.send_alert(ALERT, settings, client=client)
    assert result.ntfy
    assert not result.feed  # no key configured
    post = client.posts[0]
    assert post["url"] == "https://ntfy.example/alerts"
    assert post["headers"]["Title"] == ALERT["title"]
    assert post["headers"]["Tags"] == "eye"
    assert json.loads(post["content"].decode()) == ALERT


def test_feed_post_signed_and_verifiable(tmp_path, monkeypatch):
    key_b64, public_key = _feed_key()
    client = FakePostClient()
    settings = Settings(
        ntfy_webhook=None,
        feed_url="https://feed.example/api/ingest",
        feed_key=key_b64,
        feed_key_id="test-key",
    )
    result = special_alert.send_alert(ALERT, settings, client=client)
    assert result.feed
    post = next(p for p in client.posts if "feed" in p["url"])
    headers = post["headers"]
    body = post["content"]
    timestamp = headers["webhook-timestamp"]
    assert headers["webhook-key-id"] == "test-key"
    expected_id = hashlib.sha256(f"{timestamp}.".encode() + body).hexdigest()
    assert headers["webhook-id"] == expected_id
    signature = base64.b64decode(headers["webhook-signature"].removeprefix("v1="))
    public_key.verify(signature, f"{expected_id}.{timestamp}.".encode() + body)


def test_deterministic_webhook_id_for_same_timestamp(monkeypatch):
    key_b64, _ = _feed_key()
    monkeypatch.setattr(special_alert.time, "time", lambda: 1_700_000_000)
    body = json.dumps(ALERT).encode()
    h1 = special_alert.sign_feed_body(key_b64, "k", body)
    h2 = special_alert.sign_feed_body(key_b64, "k", body)
    assert h1 == h2


def test_feed_skipped_without_key(tmp_path, monkeypatch):
    client = FakePostClient()
    settings = Settings(
        ntfy_webhook="https://ntfy.example/alerts",
        feed_url="https://feed.example/api/ingest",
        feed_key=None,
    )
    result = special_alert.send_alert(ALERT, settings, client=client)
    assert result.ntfy
    assert not result.feed
    assert all("feed" not in p["url"] for p in client.posts)


def test_sink_failure_never_raises(tmp_path, monkeypatch):
    client = FakePostClient(fail_urls={"https://ntfy.example/alerts"})
    settings = Settings(ntfy_webhook="https://ntfy.example/alerts")
    result = special_alert.send_alert(ALERT, settings, client=client)
    assert not result.ntfy
    assert result.reason
