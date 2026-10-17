"""The localhost stub servers, driven through the real check_pr and send_alert."""

from __future__ import annotations

import httpx
import pytest

from triage_agent import pr_backstop, special_alert
from triage_agent.config import Settings

from .stub_github import AlertSinkStub, GitHubApiStub

EXPECTED = {"title": "FP triage: niri-screenshare", "body": "rendered body"}
PR_URL = "https://github.com/acme/trustsight/pull/42"


@pytest.fixture(autouse=True)
def stub_render(monkeypatch):
    monkeypatch.setattr(
        pr_backstop, "harness_render_pr", lambda *a, **k: dict(EXPECTED)
    )


def _check(github: GitHubApiStub):
    return pr_backstop.check_pr(
        pr_url=github.pr_url,
        verify_result={"kind": "FP"},
        token="dry-run-token",
        client=httpx.Client(),
        api_base=github.api_base,
    )


def test_match_passes_without_close():
    with GitHubApiStub(pr=dict(EXPECTED)) as github:
        result = _check(github)
        assert result.ok
        assert result.reason is None
        assert github.patches == []


def test_mismatch_closes_pr():
    pr = dict(EXPECTED)
    pr["body"] = "tampered body"
    with GitHubApiStub(pr=pr) as github:
        result = _check(github)
        assert not result.ok
        assert "mismatch" in result.reason
        assert len(github.patches) == 1
        assert github.pr["state"] == "closed"


def test_missing_pr_returns_no_pr_found():
    with GitHubApiStub(status=404) as github:
        result = _check(github)
        assert not result.ok
        assert result.reason == "no PR found"
        assert github.patches == []


def test_stub_pr_url_matches_owner_repo_number():
    with GitHubApiStub(owner="o", repo="r", number=7, pr=dict(EXPECTED)) as github:
        assert github.pr_url == "https://github.com/o/r/pull/7"
        result = pr_backstop.check_pr(
            pr_url=github.pr_url,
            verify_result={"kind": "FP"},
            token="t",
            client=httpx.Client(),
            api_base=github.api_base,
        )
        assert result.ok


def test_alert_sink_records_post():
    alert = {"event": "trustsight.confirmed-ioc", "package": "x"}
    with AlertSinkStub() as sink:
        result = special_alert.send_alert(
            alert, Settings(ntfy_webhook=sink.url), client=httpx.Client()
        )
        assert result.ntfy
        assert len(sink.received) == 1
        assert sink.received[0]["body"] == alert
        assert sink.received[0]["path"] == "/alerts"
