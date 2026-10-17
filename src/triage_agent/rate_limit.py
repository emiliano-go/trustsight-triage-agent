"""Backoff scheduling and the warp rotation policy.

:class:`BackoffSchedule` is pure: delays depend only on the attempt number
and the injected jitter RNG, so tests fix the RNG and get determinism.
:class:`RotationPolicy` decides, given a detected rate limit and how many
rotations have been used, whether to rotate the warp egress, fall back to
the secondary model, or fail the job.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable
from dataclasses import dataclass

MIN_DELAY_SECONDS = 30.0
MAX_DELAY_SECONDS = 900.0
BACKOFF_FACTOR = 2.0
JITTER_FRACTION = 0.25

_ACTION_ROTATE = "rotate"
_ACTION_FALLBACK = "fallback_model"
_ACTION_FAIL = "fail"


class BackoffError(ValueError):
    pass


class BackoffSchedule:
    """Exponential backoff with jitter: delay = min * factor**(attempt-1)."""

    def __init__(
        self,
        minimum: float = MIN_DELAY_SECONDS,
        maximum: float = MAX_DELAY_SECONDS,
        factor: float = BACKOFF_FACTOR,
        *,
        jitter: float = JITTER_FRACTION,
        rng: Callable[[], float] | None = None,
    ) -> None:
        if minimum <= 0:
            raise BackoffError("minimum must be positive")
        if maximum < minimum:
            raise BackoffError("maximum must be >= minimum")
        if factor < 1:
            raise BackoffError("factor must be >= 1")
        if not 0 <= jitter < 1:
            raise BackoffError("jitter must be in [0, 1)")
        self.minimum = float(minimum)
        self.maximum = float(maximum)
        self.factor = float(factor)
        self.jitter = float(jitter)
        self._rng = rng or random.random

    def next_delay(self, attempt: int) -> float:
        """Delay in seconds before retry *attempt* (1-based)."""

        if attempt < 1:
            raise BackoffError("attempt is 1-based")
        base = min(self.maximum, self.minimum * self.factor ** (attempt - 1))
        jitter = self._rng() * self.jitter
        return round(base * (1 + jitter), 6)


def detect_429(status_or_text: object) -> bool:
    """True when an HTTP status or response body signals rate limiting."""

    if status_or_text is None:
        return False
    if isinstance(status_or_text, int):
        return status_or_text == 429
    text = str(status_or_text).lower()
    return "429" in text or "rate limit" in text


_RETRY_AFTER_RE = re.compile(
    r"retry[-_ ]?after[^0-9]{0,16}(\d{1,6})(?:\s*(?:s|sec|seconds))?\b",
    re.IGNORECASE,
)
#: Zen free-route 429s usually carry no machine-readable Retry-After header
#: (community-measured ~15-20 RPM burst cap; see the module docstring in
#: agent_job.py), so this is a best-effort floor parsed from whatever the
#: provider did echo into the output stream.


def extract_retry_after(text: object) -> float | None:
    """Seconds a provider asked us to wait, parsed from output text.

    Returns the largest ``retry[- ]after <n>`` value found, or None when the
    output carries no such hint (callers then rely on the BackoffSchedule).
    """

    if not text:
        return None
    values = [int(m) for m in _RETRY_AFTER_RE.findall(str(text))]
    return float(max(values)) if values else None


def effective_delay(
    schedule: BackoffSchedule, attempt: int, retry_after: float | None
) -> float:
    """Backoff delay for *attempt*, floored by a provider Retry-After hint."""

    delay = schedule.next_delay(attempt)
    if retry_after and retry_after > delay:
        return retry_after
    return delay


@dataclass(frozen=True)
class RotationDecision:
    action: str  # "rotate" | "fallback_model" | "fail"
    detail: str


class RotationPolicy:
    """Rotate at most *max_rotations* times on 429s, then degrade."""

    def __init__(self, max_rotations: int = 5) -> None:
        if max_rotations < 1:
            raise BackoffError("max_rotations must be >= 1")
        self.max_rotations = max_rotations

    def decide(self, *, rate_limited: bool, rotations_used: int) -> RotationDecision:
        if not rate_limited:
            return RotationDecision(_ACTION_FAIL, "not a rate limit")
        if rotations_used < self.max_rotations:
            return RotationDecision(
                _ACTION_ROTATE,
                f"rotation {rotations_used + 1}/{self.max_rotations}",
            )
        if rotations_used == self.max_rotations:
            return RotationDecision(
                _ACTION_FALLBACK, "rotation budget exhausted; using fallback model"
            )
        return RotationDecision(_ACTION_FAIL, "fallback model also rate limited")
