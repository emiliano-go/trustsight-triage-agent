from triage_agent.prompt import build_prompt


def test_prompt_contains_evidence(alerts_event):
    entry = alerts_event["over_threshold"][0]
    prompt = build_prompt(entry)
    assert "hello-aur" in prompt
    assert "rule.install-curl-pipe-sh" in prompt
    assert "1.0.0-1" in prompt and "1.1.0-1" in prompt
    assert "https://aur.archlinux.org/packages/hello-aur" in prompt
    assert "curl | sh in PKGBUILD" in prompt


def test_prompt_embeds_verdict_schema():
    prompt = build_prompt({"package": "p"})
    assert '"schema_version": 1' in prompt
    assert "/job/verdict.json" in prompt
    for tool in ("fp_agent_verify", "fp_agent_pr", "fp_agent_alert"):
        assert tool in prompt
    assert "verdict" in prompt and "confidence" in prompt
    assert "rationale" in prompt and "evidence" in prompt


def test_prompt_bans_em_dash_and_double_dash():
    prompt = build_prompt({"package": "p"})
    assert "\u2014" not in prompt
    assert " -- " not in prompt


def test_prompt_demands_code_fixes_for_fp():
    from triage_agent.prompt import build_prompt

    entry = {"package": "demo", "aur_url": "u", "rules": ["C024"],
             "findings": []}
    for open_pr in (True, False):
        text = build_prompt(entry, open_pr=open_pr)
        assert "code_fixes, REQUIRED for an FP verdict" in text
        assert "repo_file(path)" in text
        assert "git apply" in text
        assert "src/trustsight/" in text
