"""agent_job: verdict/PR extraction and the in-container entrypoint."""

import json
from types import SimpleNamespace

from triage_agent import agent_job

VERDICT_JSON = json.dumps(
    {
        "schema_version": 1,
        "package": "hello-aur",
        "verdict": "FP",
        "confidence": "high",
        "rationale": "checked",
        "evidence": {},
        "proposed_changes": {},
    }
)


def test_extract_verdict_takes_last_plausible_object():
    output = f'noise {{"schema_version": 1, "verdict": "TP"}}\n{VERDICT_JSON}'
    assert agent_job.extract_verdict(output)["verdict"] == "FP"
    assert agent_job.extract_verdict("no json here") is None
    assert agent_job.extract_verdict('{"schema_version": 2}') is None


def test_extract_pr_url_takes_last_match():
    output = (
        "opened https://github.com/acme/trustsight/pull/1 then"
        " https://github.com/acme/trustsight/pull/42"
    )
    assert agent_job.extract_pr_url(output).endswith("/pull/42")
    assert agent_job.extract_pr_url("nothing") is None


def _run_main(tmp_path, monkeypatch, rc=0, output=""):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("triage this")
    verdict_out = tmp_path / "verdict.json"
    pr_out = tmp_path / "pr_url"
    monkeypatch.setattr(agent_job, "VERDICT_PATH", verdict_out)
    monkeypatch.setattr(agent_job, "PR_URL_PATH", pr_out)
    monkeypatch.setattr(agent_job, "OUTPUT_PATH", tmp_path / "agent-output.txt")
    monkeypatch.setattr(agent_job, "PROMPT_PATH", prompt)

    def fake_run_agent(prompt_text, **kwargs):
        assert prompt_text == "triage this"
        return output + "\n" + VERDICT_JSON, rc

    monkeypatch.setattr(agent_job, "run_agent", fake_run_agent)
    return agent_job.main([]), verdict_out, pr_out


def test_main_writes_verdict_and_pr_url(tmp_path, monkeypatch):
    output = "done https://github.com/acme/trustsight/pull/9"
    rc, verdict_out, pr_out = _run_main(tmp_path, monkeypatch, output=output)
    assert rc == 0
    assert json.loads(verdict_out.read_text())["verdict"] == "FP"
    assert pr_out.read_text().strip().endswith("/pull/9")


def test_main_nonzero_exit_is_failure(tmp_path, monkeypatch):
    rc, verdict_out, _ = _run_main(
        tmp_path, monkeypatch, rc=1, output="opencode blew up"
    )
    assert rc == 1
    assert not verdict_out.exists()


def test_main_without_verdict_is_failure(tmp_path, monkeypatch):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("x")
    monkeypatch.setattr(agent_job, "PROMPT_PATH", prompt)
    monkeypatch.setattr(agent_job, "OUTPUT_PATH", tmp_path / "out.txt")
    monkeypatch.setattr(agent_job, "run_agent", lambda *a, **k: ("no verdict", 0))
    assert agent_job.main([]) == 1


def test_main_missing_prompt_is_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        agent_job, "PROMPT_PATH", tmp_path / "absent.txt"
    )
    assert agent_job.main([]) == 1


def test_run_agent_invokes_opencode():
    calls: list[dict] = {}

    def runner(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return SimpleNamespace(stdout="out", stderr="", returncode=0)

    output, rc = agent_job.run_agent(
        "prompt text", model="m", opencode="opencode-bin",
        config="cfg.json", cwd=".", timeout=9, runner=runner,
    )
    assert rc == 0 and "out" in output
    assert calls["cmd"][:2] == ["opencode-bin", "run"]
    assert "--agent" in calls["cmd"] and "triage" in calls["cmd"]
    assert calls["kwargs"]["timeout"] == 9


class TestClassifyFailure:
    def test_429_shapes_are_rate_limited(self):
        assert agent_job.classify_failure('{"message": "429 Too Many Requests"}') == "rate_limited"  # noqa: E501
        assert agent_job.classify_failure("429 rate limit") == "rate_limited"

    def test_unknownerror_and_5xx_are_transient(self):
        zen = '{"name": "UnknownError", "data": {"message": "Unexpected server error. Check server logs for details.", "ref": "err_x"}}'  # noqa: E501
        assert agent_job.classify_failure(zen) == "transient"
        assert agent_job.classify_failure("500 internal server error") == "transient"  # noqa: E501
        assert agent_job.classify_failure("fetch failed: ETIMEDOUT") == "transient"
        assert agent_job.classify_failure("stream disconnected") == "transient"
        assert agent_job.classify_failure("model overloaded, try again") == "transient"  # noqa: E501

    def test_genuine_errors_are_fatal(self):
        assert agent_job.classify_failure('agent "triage" not found') == "fatal"
        assert agent_job.classify_failure("no verdict JSON in agent output") == "fatal"  # noqa: E501
        assert agent_job.classify_failure("") == "fatal"

    def test_rate_limit_wins_over_transient(self):
        out = "500 then 429 Too Many Requests"
        assert agent_job.classify_failure(out) == "rate_limited"


def _retry_kwargs(tmp_path, runner):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("p")
    return dict(
        model="m", opencode="opencode", config=tmp_path / "c.json",
        cwd=tmp_path, timeout=5, runner=runner, sleeper=lambda s: None,
        log=lambda *a, **k: None,
    )


def test_retries_transient_then_succeeds(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        if len(attempts) < 3:
            return SimpleNamespace(stdout="", stderr="500 internal server error",
                                   returncode=1)
        return SimpleNamespace(stdout=VERDICT_JSON, stderr="", returncode=0)

    output, rc = agent_job.run_with_retries("p", **_retry_kwargs(tmp_path, runner))
    assert rc == 0
    assert len(attempts) == 3
    assert agent_job.extract_verdict(output)["verdict"] == "FP"


def test_rate_limited_does_not_burn_in_place_retries(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        return SimpleNamespace(stdout="", stderr="429 Too Many Requests",
                               returncode=1)

    _output, rc = agent_job.run_with_retries("p", **_retry_kwargs(tmp_path, runner))
    assert rc == agent_job.EXIT_RATE_LIMITED
    assert len(attempts) == 1


def test_fatal_fails_fast(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        return SimpleNamespace(stdout="", stderr='agent "triage" not found',
                               returncode=1)

    _output, rc = agent_job.run_with_retries("p", **_retry_kwargs(tmp_path, runner))
    assert rc == agent_job.EXIT_FAILURE
    assert len(attempts) == 1


def test_timeout_is_transient_and_retries(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise __import__("subprocess").TimeoutExpired(cmd, 5)
        return SimpleNamespace(stdout=VERDICT_JSON, stderr="", returncode=0)

    _output, rc = agent_job.run_with_retries("p", **_retry_kwargs(tmp_path, runner))
    assert rc == 0
    assert len(attempts) == 2


def test_exhausted_transient_budget_fails(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        return SimpleNamespace(stdout="", stderr="500 server error",
                               returncode=1)

    _output, rc = agent_job.run_with_retries("p", **_retry_kwargs(tmp_path, runner))
    assert rc == agent_job.EXIT_FAILURE
    assert len(attempts) == agent_job.MAX_IN_PLACE_RETRIES


def test_main_returns_3_on_rate_limit(tmp_path, monkeypatch):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("x")
    monkeypatch.setattr(agent_job, "PROMPT_PATH", prompt)
    monkeypatch.setattr(agent_job, "OUTPUT_PATH", tmp_path / "out.txt")
    monkeypatch.setattr(
        agent_job, "run_agent",
        lambda *a, **k: ("429 Too Many Requests", 1),
    )
    assert agent_job.main([]) == agent_job.EXIT_RATE_LIMITED


def test_main_never_invokes_warp(tmp_path, monkeypatch):
    """agent_job must not touch warp-cli; egress is ambient (entrypoint)."""

    class Boom:
        def __init__(self, *a, **k):
            raise AssertionError("WarpManager must not be constructed")

    monkeypatch.setattr("triage_agent.warp.WarpManager", Boom)
    monkeypatch.setenv("ENABLE_WARP_ROTATION", "1")
    output = "done https://github.com/acme/trustsight/pull/9"
    rc, _verdict_out, _pr_out = _run_main(tmp_path, monkeypatch, output=output)
    assert rc == 0


def test_timeout_keeps_partial_output(tmp_path):
    attempts = []

    def runner(cmd, **kwargs):
        attempts.append(1)
        exc = __import__("subprocess").TimeoutExpired(cmd, 5)
        exc.stdout = "partial model text"
        exc.stderr = b"and bytes"
        raise exc

    output, rc = agent_job.run_with_retries(
        "p", **_retry_kwargs(tmp_path, runner))
    assert rc == agent_job.EXIT_FAILURE
    assert "partial model text" in output
    assert "and bytes" in output
    assert len(attempts) == agent_job.MAX_IN_PLACE_RETRIES
