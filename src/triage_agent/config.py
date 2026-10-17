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
    model: str = "opencode/MiMo-V2.6-Flash"
    job_root: str = "/job"
    harness_cli: str = "harness"
    harness_timeout_seconds: int = 900
    warp: WarpSettings = field(default_factory=WarpSettings)

    def __post_init__(self) -> None:
        if self.poll_interval_seconds < 1:
            raise ConfigError("poll_interval_seconds must be >= 1")
        if not self.feed_url.startswith(("https://", "http://")):
            raise ConfigError(f"feed_url must be an http(s) URL, got {self.feed_url!r}")
        if self.harness_timeout_seconds < 1:
            raise ConfigError("harness_timeout_seconds must be >= 1")

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
            model=e.get("TRIAGE_MODEL", "opencode/MiMo-V2.6-Flash").strip()
            or "opencode/MiMo-V2.6-Flash",
            job_root=e.get("TRIAGE_JOB_ROOT", "/job").strip() or "/job",
            harness_cli=e.get("TRIAGE_HARNESS_CLI", "harness").strip() or "harness",
            harness_timeout_seconds=_int(
                e, "TRIAGE_HARNESS_TIMEOUT_SECONDS", 900, minimum=1
            ),
            warp=warp,
        )

    def require_job_secrets(self) -> None:
        """Secrets only a real job run needs (not unit tests, not dry runs)."""

        missing = [
            name
            for name, value in (
                ("GITHUB_PERSONAL_ACCESS_TOKEN", self.github_token),
                ("TRUSTSIGHT_FEED_KEY", self.feed_key),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "missing required job secrets: " + ", ".join(missing)
            )
