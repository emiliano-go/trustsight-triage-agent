"""pr_backstop against a fake GitHub API client and a stubbed harness render."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage_agent import pr_backstop

REAL_RENDER = pr_backstop.harness_render_pr

PR_URL = "https://github.com/acme/trustsight/pull/42"
EXPECTED = {"branch": "triage/fp-hello-aur-deadbeef", "title": "FP triage: hello-aur",
            "body": "| Finding | False trigger | Fix |\n|---|---|---|\n"}


class FakeApiResponse:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.content = b"{}"

    def json(self):
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeApiClient:
    """Records requests; serves canned GET/PATCH responses."""

    def __init__(self, get_status: int = 200, pr: dict | None = None):
        self.get_status = get_status
        self.pr = pr if pr is not None else dict(EXPECTED)
        self.requests: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        if method == "GET":
            return FakeApiResponse(self.get_status, self.pr)
        return FakeApiResponse(200, {"state": "closed"})


@pytest.fixture(autouse=True)
def stub_render(monkeypatch):
    monkeypatch.setattr(
        pr_backstop, "harness_render_pr", lambda *a, **k: dict(EXPECTED)
    )


def run(client, **kwargs):
    return pr_backstop.check_pr(
        pr_url=kwargs.pop("pr_url", PR_URL),
        verify_result={"kind": "FP"},
        token="tok",
        client=client,
        cli="harness",
    )


def test_match_passes_without_close():
    client = FakeApiClient()
    result = run(client)
    assert result.ok
    assert all(r["method"] == "GET" for r in client.requests)


def test_mismatch_closes_pr():
    pr = dict(EXPECTED)
    pr["body"] = "tampered body"
    client = FakeApiClient(pr=pr)
    result = run(client)
    assert not result.ok
    patch = [r for r in client.requests if r["method"] == "PATCH"]
    assert len(patch) == 1
    assert patch[0]["json"] == {"state": "closed"}
    assert "mismatch" in result.reason


def test_title_mismatch_closes_pr():
    pr = dict(EXPECTED)
    pr["title"] = "FP triage: other-pkg"
    client = FakeApiClient(pr=pr)
    result = run(client)
    assert not result.ok
    assert result.reason.startswith("title mismatch")


def test_missing_pr_fails_with_reason():
    client = FakeApiClient(get_status=404, pr={"message": "Not Found"})
    result = run(client)
    assert not result.ok
    assert result.reason == "no PR found"
    assert all(r["method"] == "GET" for r in client.requests)


def test_missing_token_fails_before_any_call():
    client = FakeApiClient()
    result = pr_backstop.check_pr(
        pr_url=PR_URL, verify_result={"kind": "FP"}, token=None, client=client
    )
    assert not result.ok
    assert "token" in result.reason
    assert client.requests == []


def test_bad_url_fails():
    client = FakeApiClient()
    result = run(client, pr_url="https://example.com/not-a-pr")
    assert not result.ok
    assert client.requests == []


def test_parse_pr_url():
    assert pr_backstop.parse_pr_url(PR_URL) == ("acme", "trustsight", 42)
    assert pr_backstop.parse_pr_url(PR_URL + "/") == ("acme", "trustsight", 42)
    with pytest.raises(pr_backstop.BackstopError):
        pr_backstop.parse_pr_url("not a url")


def test_render_failure_is_reported(monkeypatch):
    def boom(*a, **k):
        raise pr_backstop.BackstopError("harness down")

    monkeypatch.setattr(pr_backstop, "harness_render_pr", boom)
    result = run(FakeApiClient())
    assert not result.ok
    assert "harness down" in result.reason


def test_render_pr_cli_argv(monkeypatch):
    """The real harness_render_pr must call the documented CLI flags."""

    class Proc:
        returncode = 0
        stdout = json.dumps(EXPECTED)
        stderr = ""

    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        path = cmd[cmd.index("--result") + 1]
        calls["result_path"] = path
        calls["sent"] = json.loads(Path(path).read_text())
        return Proc()

    monkeypatch.setattr(pr_backstop.subprocess, "run", fake_run)
    monkeypatch.setattr(pr_backstop, "harness_render_pr", REAL_RENDER)
    rendered = pr_backstop.harness_render_pr(
        {"kind": "FP"}, target_repo="trustsight-harness", day="2026-10-16",
        cli="harness", timeout=7,
    )
    assert rendered == EXPECTED
    assert calls["cmd"][:2] == ["harness", "fp_agent_pr"]
    assert calls["cmd"][2] == "--result"
    assert calls["cmd"][4:10:2] == ["--target-repo", "--date"]
    assert calls["cmd"][5] == "trustsight-harness"
    assert calls["cmd"][7] == "2026-10-16"
    assert calls["kwargs"]["timeout"] == 7
    assert not Path(calls["result_path"]).exists()
    assert calls["sent"] == {"kind": "FP"}


class FakeListClient:
    """Serves the pulls list endpoint; records the head filter."""

    def __init__(self, items=None, status=200):
        self.items = items if items is not None else []
        self.status = status
        self.requests: list[dict] = []

    def request(self, method, url, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        if self.status >= 400:
            return FakeApiResponse(self.status, {"message": "Not Found"})
        return FakeApiResponse(200, list(self.items))


def test_find_pr_matches_head_filter():
    client = FakeListClient(
        [{"html_url": PR_URL, "head": {"ref": "triage/x"}}]
    )
    found = pr_backstop.find_pr(
        branch="triage/x", repo="acme/trustsight", token="tok", client=client
    )
    assert found == PR_URL
    assert client.requests[0]["params"]["head"] == "triage/x"


def test_find_pr_prefixes_owner_when_known():
    client = FakeListClient([{"html_url": PR_URL}])
    pr_backstop.find_pr(
        branch="triage/x", repo="acme/trustsight", token="tok", client=client,
        head_owner="bot",
    )
    assert client.requests[0]["params"]["head"] == "bot:triage/x"


def test_find_pr_returns_none_on_empty_or_404():
    assert pr_backstop.find_pr(
        branch="b", repo="r/r", token="t", client=FakeListClient([])
    ) is None
    assert pr_backstop.find_pr(
        branch="b", repo="r/r", token="t", client=FakeListClient(status=404)
    ) is None


def test_check_pr_discovery_uses_render_branch(monkeypatch):
    """discover_branch: find via list endpoint, then verify the found PR."""
    branch = EXPECTED["branch"]
    client = FakeApiClient(pr=dict(EXPECTED))
    # Route the list call through a client that answers both shapes.
    list_client = FakeListClient(
        [{"html_url": PR_URL, "head": {"ref": branch}}]
    )

    class Both:
        def request(self, method, url, **kwargs):
            if url.endswith("/pulls"):
                return list_client.request(method, url, **kwargs)
            return client.request(method, url, **kwargs)

    result = pr_backstop.check_pr(
        pr_url=None,
        verify_result={"kind": "FP"},
        token="tok",
        client=Both(),
        discover_branch=True,
        pr_owner="acme",
    )
    assert result.ok
    assert result.pr_url == PR_URL
    assert list_client.requests[0]["params"]["state"] == "open"
