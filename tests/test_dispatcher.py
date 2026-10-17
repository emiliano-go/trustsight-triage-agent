import httpx
import pytest

from triage_agent.dispatcher import (
    Deduper,
    event_digest,
    poll_once,
    rows_from_feed,
)
from triage_agent.queue import JobQueue

from .conftest import FakeHttpClient


@pytest.fixture()
def queue(tmp_path):
    with JobQueue(tmp_path / "jobs.sqlite3") as q:
        yield q


def feed_rows(payloads):
    return [{"id": str(i), "payload": p} for i, p in enumerate(payloads)]


def test_rows_from_feed_accepts_envelope_and_bare():
    payload = {"event": "trustsight.alerts", "alerts": [], "over_threshold": []}
    assert len(rows_from_feed({"rows": [{"payload": payload}]})) == 1
    assert len(rows_from_feed([{"payload": payload}])) == 1
    assert len(rows_from_feed([{"payload": '{"event": "trustsight.alerts"}'}])) == 1
    assert rows_from_feed([{"payload": "not json"}]) == []
    assert rows_from_feed([{"payload": {"event": "other"}}]) == []
    assert rows_from_feed({"unexpected": 1}) == []


def test_same_event_enqueues_once(queue, alerts_event):
    client = FakeHttpClient(feed_rows([alerts_event]))
    deduper = Deduper()
    first = list(poll_once(client, "https://feed.example.org", queue, deduper))
    second = list(poll_once(client, "https://feed.example.org", queue, deduper))
    assert len(first) == 1
    assert first[0][1] == "hello-aur"
    assert second == []
    assert len(queue.by_status("queued")) == 1


def test_new_cycle_enqueues(queue, alerts_event, ioc_event):
    client = FakeHttpClient(feed_rows([alerts_event]))
    deduper = Deduper()
    list(poll_once(client, "https://feed.example.org", queue, deduper))
    # next cycle: new payload appended, poll returns both rows
    client2 = FakeHttpClient(feed_rows([alerts_event, ioc_event]))
    jobs = list(poll_once(client2, "https://feed.example.org", queue, deduper))
    assert len(jobs) == 1
    job_id, package = jobs[0]
    assert package == "evil-aur"
    assert queue.get(job_id).kind == "ioc"


def test_ioc_entry_marked_ioc_kind(queue, ioc_event):
    client = FakeHttpClient(feed_rows([ioc_event]))
    jobs = list(poll_once(client, "https://feed.example.org", queue, Deduper()))
    assert queue.get(jobs[0][0]).kind == "ioc"


def test_network_failure_never_raises(queue):
    client = FakeHttpClient(exc=httpx.ConnectError("down"))
    assert list(poll_once(client, "https://feed.example.org", queue, Deduper())) == []


def test_http_error_never_raises(queue, alerts_event):
    class Boom(FakeHttpClient):
        def get(self, url, **kwargs):
            import httpx

            raise httpx.HTTPStatusError("429", request=None, response=None)

    assert list(poll_once(Boom(), "https://feed.example.org", queue, Deduper())) == []


def test_event_digest_changes_with_cycle(alerts_event):
    d1 = event_digest(alerts_event)
    alerts_event["cycle"] = 99  # same alert content, different metadata
    assert event_digest(alerts_event) == d1
    alerts_event["alerts"] = alerts_event["alerts"] + [
        {"package": "x", "rule_id": "r"}
    ]
    assert event_digest(alerts_event) != d1


def test_poll_uses_feed_api_params(queue, alerts_event):
    client = FakeHttpClient(feed_rows([alerts_event]))
    list(poll_once(client, "https://feed.example.org/", queue, Deduper()))
    req = client.requests[0]
    assert req["url"] == "https://feed.example.org/api/feed"
    assert req["params"] == {"event": "trustsight.alerts", "limit": 50}
    assert req["timeout"] > 0


class _RoutingClient:
    """Fake HTTP client routing /api/feed and /api/messages separately."""

    def __init__(self, feed_body, messages):
        self._feed_body = feed_body
        self._messages = messages
        self.requests = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        if "/api/messages/" in url:
            slug = url.rsplit("/api/messages/", 1)[1]
            return FakeResponse(self._messages[slug])
        return FakeResponse(self._feed_body)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_fetch_events_falls_back_to_message_endpoint_for_projection_rows():
    from triage_agent.dispatcher import fetch_events

    full = {"event": "trustsight.alerts", "alerts": [],
            "over_threshold": [{"package": "tabctl"}]}
    client = _RoutingClient(
        {"items": [{"slug": "2026-10-17/131453", "event": "trustsight.alerts",
                    "title": "campaign"}]},
        {"2026-10-17/131453": {"payload": full}},
    )
    events = fetch_events(client, "https://feed.example")
    assert events == [full]
    assert any("/api/messages/2026-10-17/131453" in u for u in client.requests)


def test_fetch_events_keeps_embedded_payload_without_extra_fetch():
    from triage_agent.dispatcher import fetch_events

    full = {"event": "trustsight.alerts", "alerts": [],
            "over_threshold": [{"package": "tabctl"}]}
    client = _RoutingClient(
        {"items": [{"payload": full}]}, {}
    )
    assert fetch_events(client, "https://feed.example") == [full]
    assert len(client.requests) == 1
