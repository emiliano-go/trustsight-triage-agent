import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def alerts_event() -> dict:
    return json.loads((FIXTURES / "alerts_event.json").read_text())


@pytest.fixture()
def ioc_event() -> dict:
    return json.loads((FIXTURES / "alerts_event_ioc.json").read_text())


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class FakeHttpClient:
    """Stand-in for the httpx slice the dispatcher uses."""

    def __init__(self, payload=None, exc: Exception | None = None):
        self._payload = payload
        self._exc = exc
        self.requests: list[dict] = []

    def get(self, url: str, **kwargs):
        self.requests.append({"url": url, **kwargs})
        if self._exc is not None:
            raise self._exc
        return FakeResponse(self._payload)
