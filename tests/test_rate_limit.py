"""BackoffSchedule determinism, detect_429, and RotationPolicy decisions."""

from __future__ import annotations

import pytest

from triage_agent.rate_limit import (
    BackoffError,
    BackoffSchedule,
    RotationPolicy,
    detect_429,
    effective_delay,
    extract_retry_after,
)


def test_defaults_double_from_thirty_to_fifteen_minutes():
    schedule = BackoffSchedule(rng=lambda: 0.0)
    assert schedule.next_delay(1) == 30.0
    assert schedule.next_delay(2) == 60.0
    assert schedule.next_delay(3) == 120.0
    assert schedule.next_delay(5) == 480.0


def test_cap_at_maximum():
    schedule = BackoffSchedule(rng=lambda: 0.0)
    assert schedule.next_delay(6) == 900.0
    assert schedule.next_delay(20) == 900.0


def test_jitter_is_deterministic_with_injected_rng():
    schedule = BackoffSchedule(rng=lambda: 0.5)
    assert schedule.next_delay(1) == round(30.0 * 1.125, 6)


def test_validation():
    with pytest.raises(BackoffError):
        BackoffSchedule(minimum=0)
    with pytest.raises(BackoffError):
        BackoffSchedule(minimum=10, maximum=5)
    with pytest.raises(BackoffError):
        BackoffSchedule(factor=0.5)
    with pytest.raises(BackoffError):
        BackoffSchedule(jitter=1.0)
    with pytest.raises(BackoffError):
        BackoffSchedule(jitter=-0.1)
    schedule = BackoffSchedule(rng=lambda: 0.0)
    with pytest.raises(BackoffError):
        schedule.next_delay(0)


def test_zero_jitter_is_fully_deterministic():
    schedule = BackoffSchedule(jitter=0.0)
    assert schedule.next_delay(1) == 30.0
    assert schedule.next_delay(3) == 120.0


def test_detect_429_status_and_body():
    assert detect_429(429)
    assert not detect_429(200)
    assert detect_429("HTTP 429 Too Many Requests")
    assert detect_429('{"message": "API rate limit exceeded"}')
    assert not detect_429("normal body")
    assert not detect_429(None)


def test_rotation_policy_budget():
    policy = RotationPolicy(max_rotations=2)
    decision = policy.decide(rate_limited=False, rotations_used=0)
    assert decision.action == "fail"
    assert policy.decide(rate_limited=True, rotations_used=0).action == "rotate"
    assert policy.decide(rate_limited=True, rotations_used=1).action == "rotate"
    fallback = policy.decide(rate_limited=True, rotations_used=2)
    assert fallback.action == "fallback_model"
    final = policy.decide(rate_limited=True, rotations_used=3)
    assert final.action == "fail"


def test_rotation_policy_validation():
    with pytest.raises(BackoffError):
        RotationPolicy(max_rotations=0)


def test_extract_retry_after_parses_seconds_hints():
    assert extract_retry_after("HTTP 429; retry-after: 42") == 42.0
    assert extract_retry_after("please retry after 7 seconds") == 7.0
    assert extract_retry_after('{"retryAfter": 120}') == 120.0
    # largest hint wins when several appear
    assert extract_retry_after("retry-after: 10 ... retry after 60s") == 60.0
    assert extract_retry_after("no hint here") is None
    assert extract_retry_after("") is None
    assert extract_retry_after(None) is None


def test_effective_delay_floors_schedule_with_retry_after():
    schedule = BackoffSchedule(rng=lambda: 0.0)
    # schedule says 30s; provider asked for 90s -> wait 90s
    assert effective_delay(schedule, 1, 90.0) == 90.0
    # provider asked for 5s; schedule is the floor -> wait 30s
    assert effective_delay(schedule, 1, 5.0) == 30.0
    # no hint -> plain schedule
    assert effective_delay(schedule, 2, None) == 60.0
