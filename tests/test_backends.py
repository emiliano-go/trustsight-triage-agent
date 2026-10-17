"""ReplayBackend: canned verdict replay for dry runs and tests."""

from __future__ import annotations

import pytest

from triage_agent.backends import ReplayBackend
from triage_agent.runner import VerdictError, load_verdict


def _fixture(name: str):
    from pathlib import Path

    return Path(__file__).parent / "fixtures" / name


def test_replays_canned_verdict(tmp_path):
    backend = ReplayBackend(_fixture("verdict_niri_screenshare_fp.json"),
                            pr_url="https://github.com/acme/trustsight/pull/1")
    path = backend.run(prompt="p", job_id="j1", job_root=str(tmp_path))
    verdict = load_verdict(path)
    assert verdict["package"] == "niri-screenshare"
    assert verdict["verdict"] == "FP"
    assert verdict["findings"][0]["rule_id"] == "H020"
    assert backend.calls == [{"prompt": "p", "job_id": "j1"}]
    assert backend.last_pr_url.endswith("/pull/1")


def test_exposes_last_pr_url_none_by_default(tmp_path):
    backend = ReplayBackend(_fixture("verdict_niri_screenshare_fp.json"))
    assert backend.last_pr_url is None


def test_missing_fixture_fails_closed(tmp_path):
    backend = ReplayBackend(tmp_path / "nope.json")
    with pytest.raises(VerdictError, match="canned verdict not found"):
        backend.run(prompt="p", job_id="j1", job_root=str(tmp_path))
    assert backend.calls == []
