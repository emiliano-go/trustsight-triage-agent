"""Environment-driven settings.

Every value comes from the environment; there are no silent defaults for
secrets. Job secrets that only a real run needs are enforced separately by
:meth:`Settings.require_job_secrets`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .rate_limit import BackoffError, BackoffSchedule


class ConfigError(ValueError):
    """A required setting is missing or invalid."""


_DEFAULT_FEED_URL = "https://watcher.trustsight.org"


def _required(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required but not set")
    return value


def _optional(env: dict[str, str], name: str) -> str | None:
    value = env.get(name, "").strip()
    return value or None


def _int(env: dict[str, str], name: str, default: int, *, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _float(env: dict[str, str], name: str, default: float, *, minimum: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


@dataclass(frozen=True)
class WarpSettings:
    """Sandbox warp rotation. Consumed by warp.py and rate_limit.py.

    These defaults are the real schedule values (see rate_limit.BackoffSchedule):
    exponential backoff, factor 2, 30 s to a 900 s cap, 25% jitter.
    """

    enable_rotation: bool = True
    max_rotations: int = 5
    backoff_min_seconds: float = 30.0
    backoff_max_seconds: float = 900.0
    backoff_factor: float = 2.0
    backoff_jitter: float = 0.25

    def __post_init__(self) -> None:
        if self.max_rotations < 1:
            raise ConfigError("max_rotations must be >= 1")
        try:
            self.schedule()
        except BackoffError as exc:
            raise ConfigError(str(exc)) from exc

    def schedule(self) -> BackoffSchedule:
        """The single source of truth for retry delays, built from these values."""

        return BackoffSchedule(
            self.backoff_min_seconds,
            self.backoff_max_seconds,
            self.backoff_factor,
            jitter=self.backoff_jitter,
        )


@dataclass(frozen=True)
class Settings:
    feed_url: str = _DEFAULT_FEED_URL
    poll_interval_seconds: int = 120
    ntfy_webhook: str | None = None
    feed_key: str | None = None
    feed_key_id: str = "triage-agent"
    github_token: str | None = None
    opencode_api_key: str | None = None
    model: str = "opencode/longcat-2.5-preview-free"
    model_profile: str = "zen"
    model_explicit: bool = False
    job_root: str = "/job"
    harness_cli: str = "harness"
    harness_timeout_seconds: int = 900
    stale_job_seconds: int = 1800
    worker_poll_seconds: int = 30
    job_timeout_seconds: int = 3600
    triage_image: str = "trustsight-triage-agent:live"
    docker_network: str | None = None
    docker_host: str | None = None
    docker_memory_mb: int | None = None
    docker_cpus: float | None = None
    github_owner: str | None = None
    warp: WarpSettings = field(default_factory=WarpSettings)

    def __post_init__(self) -> None:
        if self.poll_interval_seconds < 1:
            raise ConfigError("poll_interval_seconds must be >= 1")
        if not self.feed_url.startswith(("https://", "http://")):
            raise ConfigError(f"feed_url must be an http(s) URL, got {self.feed_url!r}")
        if self.harness_timeout_seconds < 1:
            raise ConfigError("harness_timeout_seconds must be >= 1")
        # Fail fast on a typo'd model profile (function-level import:
        # model_profile itself imports ConfigError from this module).
        from .model_backends import resolve_profile

        resolve_profile(self.model_profile)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        """Build settings from an environment mapping (defaults to os.environ).

        Raises ConfigError on anything missing or malformed; nothing secret
        falls back to a silent default.
        """

        e = os.environ if env is None else env
        warp = WarpSettings(
            enable_rotation=_bool(e, "TRIAGE_WARP_ROTATION", True),
            max_rotations=_int(e, "TRIAGE_WARP_MAX_ROTATIONS", 5, minimum=1),
            backoff_min_seconds=_float(
                e, "TRIAGE_WARP_BACKOFF_MIN", 30.0, minimum=0.1
            ),
            backoff_max_seconds=_float(
                e, "TRIAGE_WARP_BACKOFF_MAX", 900.0, minimum=0.1
            ),
            backoff_factor=_float(e, "TRIAGE_WARP_BACKOFF_FACTOR", 2.0, minimum=1.0),
            backoff_jitter=_float(e, "TRIAGE_WARP_BACKOFF_JITTER", 0.25, minimum=0.0),
        )
        return cls(
            feed_url=e.get("TRUSTSIGHT_FEED_URL", _DEFAULT_FEED_URL).strip()
            or _DEFAULT_FEED_URL,
            poll_interval_seconds=_int(
                e, "TRIAGE_POLL_INTERVAL_SECONDS", 120, minimum=1
            ),
            ntfy_webhook=_optional(e, "TRUSTSIGHT_NTFY_WEBHOOK"),
            feed_key=_optional(e, "TRUSTSIGHT_FEED_KEY"),
            feed_key_id=e.get("TRUSTSIGHT_FEED_KEY_ID", "triage-agent").strip()
            or "triage-agent",
            github_token=_optional(e, "GITHUB_PERSONAL_ACCESS_TOKEN"),
            opencode_api_key=_optional(e, "OPENCODE_API_KEY"),
            model=e.get("TRIAGE_MODEL", "opencode/longcat-2.5-preview-free").strip()
            or "opencode/longcat-2.5-preview-free",
            model_profile=e.get("TRIAGE_MODEL_PROFILE", "zen").strip() or "zen",
            model_explicit=bool(e.get("TRIAGE_MODEL", "").strip()),
            job_root=e.get("TRIAGE_JOB_ROOT", "/job").strip() or "/job",
            harness_cli=e.get("TRIAGE_HARNESS_CLI", "harness").strip() or "harness",
            harness_timeout_seconds=_int(
                e, "TRIAGE_HARNESS_TIMEOUT_SECONDS", 900, minimum=1
            ),
            stale_job_seconds=_int(
                e, "TRIAGE_STALE_JOB_SECONDS", 1800, minimum=1
            ),
            worker_poll_seconds=_int(
                e, "TRIAGE_WORKER_POLL_SECONDS", 30, minimum=1
            ),
            job_timeout_seconds=_int(
                e, "TRIAGE_JOB_TIMEOUT_SECONDS", 3600, minimum=1
            ),
            triage_image=e.get("TRIAGE_IMAGE", "").strip()
            or "trustsight-triage-agent:live",
            docker_network=_optional(e, "TRIAGE_DOCKER_NETWORK"),
            docker_host=_optional(e, "TRIAGE_DOCKER_HOST"),
            docker_memory_mb=_int(e, "TRIAGE_DOCKER_MEMORY_MB", 0, minimum=0)
            or None,
            docker_cpus=_float(e, "TRIAGE_DOCKER_CPUS", 0.0, minimum=0.0)
            or None,
            github_owner=_optional(e, "TRIAGE_GITHUB_OWNER"),
            warp=warp,
        )

    def require_job_secrets(self) -> None:
        """Secrets a real job run needs (not unit tests, not dry runs).

        Only the GitHub token is universally required: it gates the agent's
        PR step and the PR backstop. ``TRUSTSIGHT_FEED_KEY`` is needed solely
        to sign feed-sink alerts, and :func:`special_alert.send_alert`
        already skips the signed feed sink when it is absent, so its lack
        must not stop FP-only runs. The zen model profile additionally needs
        ``OPENCODE_API_KEY`` (OpenCode Zen route); without it the job
        containers come up but every model call fails server-side.
        """

        required = [("GITHUB_PERSONAL_ACCESS_TOKEN", self.github_token)]
        if self.model_profile == "zen":
            required.append(("OPENCODE_API_KEY", self.opencode_api_key))
        missing = [name for name, value in required if not value]
        if missing:
            raise ConfigError(
                "missing required job secrets: " + ", ".join(missing)
            )
