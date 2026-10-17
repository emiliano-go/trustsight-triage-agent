"""model_backends: profile resolution, rendering, keys, fallbacks."""

from __future__ import annotations

import json

import pytest

from triage_agent import model_backends as mb
from triage_agent.config import ConfigError, Settings


def _base() -> dict:
    return json.loads(
        json.dumps(
            {
                "model": mb.ZEN_MODEL,
                "agent": {
                    "triage": {
                        "model": mb.ZEN_MODEL,
                        "fallback_models": list(mb.ZEN_FALLBACKS),
                    }
                },
                "provider": {
                    "opencode": {"options": {"apiKey": "{env:OPENCODE_API_KEY}"}}
                },
            }
        )
    )


NVIDIA_ENV = {
    "TRIAGE_MODEL_BASE_URL": "https://integrate.api.nvidia.com/v1",
    "TRIAGE_MODEL_NAME": "nvidia/nemotron-3.5-super-vl-120b-a12b",
    "NVIDIA_API_KEY": "present",
}
OLLAMA_ENV = {
    "TRIAGE_MODEL_BASE_URL": "http://host.docker.internal:11434/v1",
    "TRIAGE_MODEL_NAME": "qwen3:8b",
}


class TestResolveProfile:
    def test_default_is_zen(self):
        assert mb.resolve_profile(None) == "zen"
        assert mb.resolve_profile("") == "zen"

    def test_known_profiles(self):
        assert mb.resolve_profile("openai-compatible") == "openai-compatible"
        assert mb.resolve_profile("zen") == "zen"

    def test_unknown_raises(self):
        with pytest.raises(ConfigError, match="unknown TRIAGE_MODEL_PROFILE"):
            mb.resolve_profile("mistral")

    def test_settings_validates_profile(self):
        with pytest.raises(ConfigError):
            Settings(model_profile="bogus")
        assert Settings(model_profile="zen").model_profile == "zen"
        s = Settings.from_env({"TRIAGE_MODEL_PROFILE": "openai-compatible",
                               "TRIAGE_MODEL": "custom/m"})
        assert s.model_profile == "openai-compatible"
        assert s.model_explicit is True


class TestParseFallbacks:
    def test_comma_list(self):
        assert mb.parse_fallbacks("a, b ,c") == ["a", "b", "c"]
        assert mb.parse_fallbacks("") == []
        assert mb.parse_fallbacks(None) == []


class TestPickKeyEnv:
    def test_priority_order(self):
        env = {"NVIDIA_API_KEY": "x", "OPENROUTER_API_KEY": "y"}
        assert mb.pick_key_env(env) == "NVIDIA_API_KEY"
        env["TRIAGE_MODEL_API_KEY"] = "z"
        assert mb.pick_key_env(env) == "TRIAGE_MODEL_API_KEY"

    def test_empty_values_ignored(self):
        assert mb.pick_key_env({"NVIDIA_API_KEY": "  "}) is None

    def test_no_key_is_fine(self):
        assert mb.pick_key_env({}) is None


class TestRenderZen:
    def test_identity_and_copy(self):
        base = _base()
        rendered = mb.render_opencode_config(base, "zen", {})
        assert rendered == base
        assert rendered is not base


class TestRenderOpenAICompatible:
    def test_nvidia_profile(self):
        rendered = mb.render_opencode_config(_base(), "openai-compatible",
                                             NVIDIA_ENV)
        ref = ("triage-custom/"
               "nvidia/nemotron-3.5-super-vl-120b-a12b")
        assert rendered["model"] == ref
        provider = rendered["provider"]["triage-custom"]
        assert provider["options"]["baseURL"] == NVIDIA_ENV[
            "TRIAGE_MODEL_BASE_URL"]
        assert provider["options"]["apiKey"] == "{env:NVIDIA_API_KEY}"
        assert "opencode" in rendered["provider"]  # zen ladder still around

    def test_ollama_local_no_key(self):
        rendered = mb.render_opencode_config(_base(), "openai-compatible",
                                             OLLAMA_ENV)
        provider = rendered["provider"]["triage-custom"]
        assert "apiKey" not in provider["options"]
        assert rendered["model"] == "triage-custom/qwen3:8b"

    def test_openrouter_alias(self):
        env = {
            "TRIAGE_MODEL_BASE_URL": "https://openrouter.ai/api/v1",
            "TRIAGE_MODEL_NAME": "meta-llama/llama-3.3-70b",
            "OPENROUTER_API_KEY": "present",
        }
        rendered = mb.render_opencode_config(_base(), "openai-compatible", env)
        assert rendered["provider"]["triage-custom"]["options"]["apiKey"] == \
            "{env:OPENROUTER_API_KEY}"

    def test_generic_key_wins_over_alias(self):
        env = dict(NVIDIA_ENV)
        env["TRIAGE_MODEL_API_KEY"] = "present"
        rendered = mb.render_opencode_config(_base(), "openai-compatible", env)
        assert rendered["provider"]["triage-custom"]["options"]["apiKey"] == \
            "{env:TRIAGE_MODEL_API_KEY}"

    def test_fallbacks_on_same_endpoint(self):
        env = dict(NVIDIA_ENV)
        env["TRIAGE_MODEL_FALLBACKS"] = "nvidia/llama-3.1-8b, other/model"
        rendered = mb.render_opencode_config(_base(), "openai-compatible", env)
        assert rendered["agent"]["triage"]["fallback_models"] == [
            "triage-custom/nvidia/llama-3.1-8b",
            "triage-custom/other/model",
        ]

    def test_reasoning_flag(self):
        env = dict(NVIDIA_ENV)
        env["TRIAGE_MODEL_REASONING"] = "1"
        rendered = mb.render_opencode_config(_base(), "openai-compatible", env)
        entry = rendered["provider"]["triage-custom"]["models"][
            "nvidia/nemotron-3.5-super-vl-120b-a12b"]
        assert entry["reasoning"] is True

    def test_missing_endpoint_or_model_raises(self):
        with pytest.raises(ConfigError, match="TRIAGE_MODEL_BASE_URL"):
            mb.render_opencode_config(_base(), "openai-compatible",
                                      {"TRIAGE_MODEL_NAME": "m"})
        with pytest.raises(ConfigError, match="TRIAGE_MODEL_NAME"):
            mb.render_opencode_config(_base(), "openai-compatible",
                                      {"TRIAGE_MODEL_BASE_URL": "http://x"})

    def test_unknown_profile_raises(self):
        with pytest.raises(ConfigError):
            mb.render_opencode_config(_base(), "bogus", {})

    def test_render_is_json_serializable(self):
        json.dumps(mb.render_opencode_config(_base(), "openai-compatible",
                                             NVIDIA_ENV))


class TestBackendEnvFlags:
    def _flags(self, monkeypatch, **env):
        from triage_agent.config import WarpSettings
        from triage_agent.docker_backend import DockerBackend

        for key in mb.PROFILE_ENV_VARS + ("OPENCODE_API_KEY",):
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        settings = Settings(warp=WarpSettings(enable_rotation=False))
        backend = DockerBackend(settings, runner=lambda *a, **k: None)
        return backend._env_flags()

    def test_profile_env_passes_bare_by_presence(self, monkeypatch):
        flags = self._flags(monkeypatch,
                            TRIAGE_MODEL_BASE_URL="https://x/v1",
                            NVIDIA_API_KEY="secret")
        assert "TRIAGE_MODEL_BASE_URL" in flags
        assert "NVIDIA_API_KEY" in flags
        assert flags[flags.index("NVIDIA_API_KEY") - 1] == "-e"
        # Never a value: no '='-suffixed copy of the secret var.
        assert "NVIDIA_API_KEY=secret" not in flags
        assert "TRIAGE_MODEL_NAME" not in flags  # absent stays absent

    def test_no_profile_env_no_flags(self, monkeypatch):
        flags = self._flags(monkeypatch)
        for name in mb.PROFILE_ENV_VARS:
            assert name not in flags
