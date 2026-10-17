"""Pluggable model backends: one opencode mount, N provider profiles.

opencode stays the agent runtime in every profile; what changes per job is
the opencode.json that ``agent_job`` renders into the container's writable
HOME at job setup time. The profile is selected purely by env
(``TRIAGE_MODEL_PROFILE``), so switching hosted provider or local AI needs
no code change and no image rebuild.

Profiles:

- ``zen`` (default): unchanged current behavior. OpenCode Zen free route,
  MiMo-V2.6 flash-free primary, the Zen fallback ladder, and the
  warp-rotation + backend fallback-model policy in ``docker_backend``.

- ``openai-compatible``: any OpenAI-compatible chat/completions endpoint,
  driven entirely by env::

      TRIAGE_MODEL_BASE_URL   e.g. https://integrate.api.nvidia.com/v1
                              (NVIDIA NIM), https://openrouter.ai/api/v1
                              (OpenRouter), or http://host.docker.internal:
                              11434/v1 (ollama), llama.cpp server, vLLM,
                              LM Studio, ...
      TRIAGE_MODEL_NAME       model id on that endpoint
      TRIAGE_MODEL_API_KEY    optional; local servers need none
      TRIAGE_MODEL_FALLBACKS  comma-separated model names on the SAME
                              endpoint, used as opencode fallback_models
      TRIAGE_MODEL_REASONING  "1/true/yes" marks the model as a reasoning
                              model in the opencode model entry

  The API key is referenced as ``{env:NAME}`` for the first of
  ``TRIAGE_MODEL_API_KEY`` / ``NVIDIA_API_KEY`` / ``OPENROUTER_API_KEY``
  present in the worker environment; the name is chosen by *presence*,
  never by reading the value, and the var reaches the container as a bare
  ``-e`` flag (same mechanism as ``GITHUB_PERSONAL_ACCESS_TOKEN``).

Retry behavior is profile-agnostic: ``agent_job.classify_failure`` buckets
the provider's output (429 -> exit 3 -> warp rotation; transient 5xx, e.g.
NVIDIA NIM's observed ~50% sustained HTTP 500 flapping -> in-place backoff
retries; anything else -> fail fast), and for the zen profile the existing
backend fallback-model run still applies. For openai-compatible profiles
the ladder is the in-config ``fallback_models`` list on the same endpoint,
and the backend's hardcoded Zen fallback model is skipped.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

from .config import ConfigError

ZEN_MODEL = "opencode/mimo-v2.6-flash-free"
ZEN_FALLBACKS = [
    "opencode/glm-5.3-flash-free",
    "opencode/nemotron-3.5-lightning-free",
]

PROFILES = ("zen", "openai-compatible")
DEFAULT_PROFILE = "zen"

#: Provider id the openai-compatible profile registers in opencode.json.
CUSTOM_PROVIDER_ID = "triage-custom"

#: Env vars that parameterize the openai-compatible profile. The backend
#: passes whichever are present as bare -e flags; secrets among them are
#: forwarded by name only.
PROFILE_ENV_VARS = (
    "TRIAGE_MODEL_BASE_URL",
    "TRIAGE_MODEL_NAME",
    "TRIAGE_MODEL_API_KEY",
    "TRIAGE_MODEL_REASONING",
    "TRIAGE_MODEL_FALLBACKS",
    "NVIDIA_API_KEY",
    "OPENROUTER_API_KEY",
)

#: Key env aliases, in priority order. The first one PRESENT (by name) in
#: the worker environment is what the rendered config references.
KEY_ENV_ALIASES = (
    "TRIAGE_MODEL_API_KEY",
    "NVIDIA_API_KEY",
    "OPENROUTER_API_KEY",
)

_TRUE_VALUES = {"1", "true", "yes", "on"}


def resolve_profile(value: str | None) -> str:
    """The active profile from TRIAGE_MODEL_PROFILE (default zen)."""

    profile = (value or "").strip() or DEFAULT_PROFILE
    if profile not in PROFILES:
        raise ConfigError(
            f"unknown TRIAGE_MODEL_PROFILE {profile!r};"
            f" expected one of {PROFILES}"
        )
    return profile


def parse_fallbacks(value: str | None) -> list[str]:
    """TRIAGE_MODEL_FALLBACKS: comma-separated model names on one endpoint."""

    return [part.strip() for part in (value or "").split(",") if part.strip()]


def pick_key_env(env: Mapping[str, str] | None = None) -> str | None:
    """The API-key env var NAME to reference, chosen by presence only."""

    source = os.environ if env is None else env
    for name in KEY_ENV_ALIASES:
        if source.get(name, "").strip():
            return name
    return None


def render_opencode_config(
    base: dict,
    profile: str,
    env: Mapping[str, str] | None = None,
) -> dict:
    """Return the effective opencode config for *profile*.

    *base* is the parsed static ``agent/opencode.json``; it is deep-copied,
    never mutated. Raises :class:`ConfigError` on an unknown profile or a
    misconfigured openai-compatible profile (fail fast rather than running
    the wrong model).
    """

    if profile not in PROFILES:
        raise ConfigError(
            f"unknown TRIAGE_MODEL_PROFILE {profile!r};"
            f" expected one of {PROFILES}"
        )
    config = json.loads(json.dumps(base))
    # Route opencode's session-title side-call through the same free/model
    # route as the job: the Zen account has no paid funds, so the default
    # title model (gpt-5.4-nano) fails every session with "Insufficient
    # account funds" (harmless but polluting, and it may contribute to
    # gateway rejections). agent.title.model is an AgentConfig override.
    primary = profile_primary_model(profile, os.environ if env is None else env)
    config.setdefault("agent", {}).setdefault("title", {})["model"] = primary
    if profile == "zen":
        return config

    source = os.environ if env is None else env
    base_url = source.get("TRIAGE_MODEL_BASE_URL", "").strip()
    model_name = source.get("TRIAGE_MODEL_NAME", "").strip()
    if not base_url:
        raise ConfigError(
            "TRIAGE_MODEL_BASE_URL is required for the"
            " openai-compatible model profile"
        )
    if not model_name:
        raise ConfigError(
            "TRIAGE_MODEL_NAME is required for the openai-compatible"
            " model profile"
        )

    options: dict[str, str] = {"baseURL": base_url}
    key_env = pick_key_env(source)
    if key_env is not None:
        # Reference by var name; the value never touches disk or argv.
        options["apiKey"] = f"{{env:{key_env}}}"

    reasoning = source.get("TRIAGE_MODEL_REASONING", "").strip().lower()
    model_entry: dict[str, object] = {"name": model_name}
    if reasoning in _TRUE_VALUES:
        model_entry["reasoning"] = True

    provider = config.setdefault("provider", {})
    provider[CUSTOM_PROVIDER_ID] = {
        "npm": "@ai-sdk/openai-compatible",
        "name": "Triage custom endpoint",
        "options": options,
        "models": {model_name: model_entry},
    }

    ref = f"{CUSTOM_PROVIDER_ID}/{model_name}"
    config["model"] = ref
    agent = config.setdefault("agent", {}).setdefault("triage", {})
    agent["model"] = ref
    # Ladder = models on the SAME endpoint only; never mix providers here
    # (cross-provider fallback for non-zen profiles is a follow-up).
    agent["fallback_models"] = [
        f"{CUSTOM_PROVIDER_ID}/{name}" for name in parse_fallbacks(
            source.get("TRIAGE_MODEL_FALLBACKS"))
    ]
    return config


def profile_primary_model(
    profile: str, env: Mapping[str, str] | None = None
) -> str:
    """The primary model id for *profile* (what jobs and probes run)."""

    if profile == "zen":
        return ZEN_MODEL
    source = os.environ if env is None else env
    return source.get("TRIAGE_MODEL_NAME", "").strip() or ZEN_MODEL
