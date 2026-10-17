import json
from pathlib import Path

import pytest

from triage_agent import runner
from triage_agent.runner import (
    LocalStubBackend,
    VerdictError,
    load_verdict,
    run_job,
    validate_verdict,
)


def valid_verdict(**over):
    doc = {
        "schema_version": 1,
        "package": "hello-aur",
        "verdict": "FP",
        "confidence": "high",
        "rationale": "inspected PKGBUILD",
        "evidence": {"rule.install-curl-pipe-sh": "checked install script"},
        "proposed_changes": {"rule.install-curl-pipe-sh": "allowlist curl|sh"},
    }
    doc.update(over)
    return doc


class TestValidate:
    def test_accepts_valid(self):
        assert validate_verdict(valid_verdict())["verdict"] == "FP"

    def test_rejects_unknown_keys(self):
        with pytest.raises(VerdictError, match="unknown keys"):
            validate_verdict(valid_verdict(extra=1))

    def test_rejects_bad_verdict(self):
        with pytest.raises(VerdictError, match="verdict"):
            validate_verdict(valid_verdict(verdict="maybe"))

    def test_rejects_bad_confidence(self):
        with pytest.raises(VerdictError, match="confidence"):
            validate_verdict(valid_verdict(confidence="very high"))

    def test_rejects_bad_schema_version(self):
        with pytest.raises(VerdictError, match="schema_version"):
            validate_verdict(valid_verdict(schema_version=2))

    def test_rejects_bad_package_name(self):
        with pytest.raises(VerdictError, match="package"):
            validate_verdict(valid_verdict(package="bad name!"))

    def test_rejects_missing_required(self):
        doc = valid_verdict()
        del doc["verdict"]
        with pytest.raises(VerdictError, match="missing keys"):
            validate_verdict(doc)

    def test_rejects_oversized_string(self):
        with pytest.raises(VerdictError, match="4096"):
            validate_verdict(valid_verdict(rationale="x" * 5000))

    def test_rejects_non_object(self):
        with pytest.raises(VerdictError):
            validate_verdict([1, 2])

    def test_rejects_oversized_doc(self):
        doc = valid_verdict(evidence={"k": "v" * 4096})
        with pytest.raises(VerdictError, match="bytes"):
            validate_verdict(doc, max_bytes=64)


def test_load_verdict_roundtrip(tmp_path):
    p = tmp_path / "verdict.json"
    p.write_text(json.dumps(valid_verdict()))
    assert load_verdict(p)["package"] == "hello-aur"


def test_load_verdict_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(valid_verdict()))
    link = tmp_path / "verdict.json"
    link.symlink_to(real)
    with pytest.raises(VerdictError, match="symlink"):
        load_verdict(link)


def fake_verify(verdict, *, cli, timeout):
    return {"ok": True, "verdict": verdict["verdict"]}


def run(tmp_path, backend, **kwargs):
    return run_job(
        job_id="j1",
        prompt="p",
        job_root=str(tmp_path),
        backend=backend,
        verify=kwargs.pop("verify", fake_verify),
        **kwargs,
    )


class TestRunJob:
    def test_happy_path_verified(self, tmp_path):
        outcome = run(tmp_path, LocalStubBackend(valid_verdict()))
        assert outcome.outcome == "verified"
        assert outcome.verify_result == {"ok": True, "verdict": "FP"}

    def test_uncertain_needs_review(self, tmp_path):
        outcome = run(tmp_path, LocalStubBackend(valid_verdict(verdict="uncertain")))
        assert outcome.outcome == "needs_review"
        assert outcome.verify_result is None

    def test_low_confidence_needs_review(self, tmp_path):
        outcome = run(
            tmp_path,
            LocalStubBackend(valid_verdict(confidence="low", verdict="TP")),
        )
        assert outcome.outcome == "needs_review"

    def test_invalid_verdict_fails(self, tmp_path):
        bad = valid_verdict()
        del bad["verdict"]
        outcome = run(tmp_path, LocalStubBackend(bad))
        assert outcome.outcome == "failed"
        assert "missing keys" in outcome.reason

    def test_backend_error_fails(self, tmp_path):
        class Boom:
            def run(self, **kwargs):
                raise RuntimeError("container blew up")

        outcome = run(tmp_path, Boom())
        assert outcome.outcome == "failed"
        assert "container blew up" in outcome.reason

    def test_verify_error_fails(self, tmp_path):
        def boom(verdict, *, cli, timeout):
            raise RuntimeError("harness down")

        outcome = run(tmp_path, LocalStubBackend(), verify=boom)
        assert outcome.outcome == "failed"
        assert "harness down" in outcome.reason

    def test_unverified_result_fails(self, tmp_path):
        def unverified(verdict, *, cli, timeout):
            return {"verified": False, "kind": "FP", "reason": "cross-check failed"}

        outcome = run(tmp_path, LocalStubBackend(), verify=unverified)
        assert outcome.outcome == "failed"
        assert "cross-check failed" in (outcome.reason or "")

    def test_harness_keys_are_accepted(self, tmp_path):
        verdict = valid_verdict()
        verdict["alert_slug"] = "2026-10-16/165917"
        verdict["version_transition"] = "0.2.3-1 to 0.2.3-2"
        verdict["findings"] = [{"rule_id": "H020", "reason": "freshness only"}]
        verdict["ioc_entries"] = [
            {"type": "domain", "value": "example.invalid"}
        ]
        outcome = run(tmp_path, LocalStubBackend(verdict))
        assert outcome.outcome == "verified"

    def test_invalid_alert_slug_fails_before_verify(self, tmp_path):
        verdict = valid_verdict()
        verdict["alert_slug"] = "made-up-slug"
        outcome = run(tmp_path, LocalStubBackend(verdict))
        assert outcome.outcome == "failed"
        assert "invalid alert_slug" in (outcome.reason or "")

    def test_empty_ioc_entries_fails_before_verify(self, tmp_path):
        verdict = valid_verdict()
        verdict["ioc_entries"] = []
        outcome = run(tmp_path, LocalStubBackend(verdict))
        assert outcome.outcome == "failed"
        assert "ioc_entries" in (outcome.reason or "")

    def test_findings_must_be_a_list(self, tmp_path):
        verdict = valid_verdict()
        verdict["findings"] = {"rule_id": "H020"}
        outcome = run(tmp_path, LocalStubBackend(verdict))
        assert outcome.outcome == "failed"
        assert "findings must be a list" in (outcome.reason or "")


def test_harness_verify_cli_invocation(monkeypatch, tmp_path):
        calls = {}

        class Proc:
            returncode = 0
            stdout = json.dumps({"ok": True})
            stderr = ""

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            calls["kwargs"] = kwargs
            # The --verdict temp file must exist during the call and hold
            # the verdict JSON; harness_verify unlinks it afterwards.
            path = cmd[cmd.index("--verdict") + 1]
            calls["verdict_path"] = path
            calls["sent"] = json.loads(Path(path).read_text())
            return Proc()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        result = runner.harness_verify(valid_verdict(), cli="harness", timeout=5)
        assert result == {"ok": True}
        assert calls["cmd"][:2] == ["harness", "fp_agent_verify"]
        assert calls["cmd"][2] == "--verdict"
        assert calls["kwargs"]["timeout"] == 5
        assert not Path(calls["verdict_path"]).exists()
        assert calls["sent"]["package"] == "hello-aur"


def test_findings_items_must_be_objects(tmp_path):
    verdict = valid_verdict()
    verdict["findings"] = ["just a string"]
    outcome = run_job(
        job_id="j1",
        prompt="p",
        job_root=str(tmp_path),
        backend=LocalStubBackend(verdict),
        verify=lambda v, **k: {"verified": True, "kind": "FP"},
    )
    assert outcome.outcome == "failed"
    assert "findings[0] must be an object" in (outcome.reason or "")


class TestCodeFixesValidation:
    BASE = {"schema_version": 1, "package": "demo", "verdict": "FP",
            "confidence": "high"}

    def _verdict(self, fixes):
        return {**self.BASE, "code_fixes": fixes}

    def test_valid_code_fixes_accepted(self):
        doc = self._verdict([{
            "path": "src/trustsight/rules/r.py",
            "diff": "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
            "summary": "s", "linked_finding": "f"}])
        assert validate_verdict(doc)["code_fixes"][0]["path"] == \
            "src/trustsight/rules/r.py"

    @pytest.mark.parametrize("fixes", [
        "nope",                        # not a list
        [42],                          # not an object
        [{"path": "x"}],               # missing keys
        [{"path": "x", "diff": 1,
          "summary": "s", "linked_finding": "f"}],   # non-string diff
    ])
    def test_invalid_code_fixes_rejected(self, fixes):
        with pytest.raises(VerdictError):
            validate_verdict(self._verdict(fixes))
