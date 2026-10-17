"""Dry-run composition, fully offline: fake verify/render, real stubs."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import dry_run  # noqa: E402


def _verify_fp(verdict, **kwargs):
    return {"verified": True, "kind": "FP", "package": verdict["package"]}


def _verify_tp(verdict, **kwargs):
    return {"verified": True, "kind": "TP", "package": verdict["package"]}


def _render_pr(result, **kwargs):
    return {"title": "FP triage: niri-screenshare", "body": "rendered body"}


@pytest.fixture(autouse=True)
def stub_backstop_render(monkeypatch):
    """check_pr re-renders internally; pin it to the same canned PR."""
    monkeypatch.setattr(
        "triage_agent.pr_backstop.harness_render_pr",
        lambda *a, **k: _render_pr(None),
    )


def _render_alert(result, **kwargs):
    return {"event": "trustsight.confirmed-ioc", "package": result["package"]}


def test_fp_mode_reaches_pr_opened(tmp_path):
    report = dry_run.run_dry_run(
        mode="fp",
        workdir=tmp_path,
        verify=_verify_fp,
        render_pr=_render_pr,
        emit=lambda text: None,
    )
    assert report.ok, report.render()
    assert report.queue_status == "pr_opened"
    assert report.pr_url == "https://github.com/acme/trustsight/pull/42"


def test_ioc_mode_reaches_alert_sent(tmp_path):
    report = dry_run.run_dry_run(
        mode="ioc",
        workdir=tmp_path,
        verify=_verify_tp,
        render_alert=_render_alert,
        emit=lambda text: None,
    )
    assert report.ok, report.render()
    assert report.queue_status == "alert_sent"
    assert report.alert_received


def test_verify_failure_fails_the_run(tmp_path):
    def boom(verdict, **kwargs):
        raise RuntimeError("harness down")

    report = dry_run.run_dry_run(
        mode="fp", workdir=tmp_path, verify=boom, emit=lambda text: None
    )
    assert not report.ok
    assert "harness down" in report.render()


def test_backstop_mismatch_fails_the_run(tmp_path):
    def tampered_pr(result, **kwargs):
        return {"title": "FP triage: niri-screenshare", "body": "tampered"}

    report = dry_run.run_dry_run(
        mode="fp",
        workdir=tmp_path,
        verify=_verify_fp,
        render_pr=tampered_pr,
        emit=lambda text: None,
    )
    assert not report.ok
    assert report.queue_status == "failed"


def test_unverified_result_fails_the_run(tmp_path):
    def unverified(verdict, **kwargs):
        return {"verified": False, "kind": "FP", "reason": "cross-check failed"}

    report = dry_run.run_dry_run(
        mode="fp",
        workdir=tmp_path,
        verify=unverified,
        render_pr=_render_pr,
        emit=lambda text: None,
    )
    assert not report.ok
