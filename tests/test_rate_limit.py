"""BackoffSchedule determinism, detect_429, and RotationPolicy decisions."""

from __future__ import annotations

import pytest

from triage_agent.rate_limit import (
    BackoffError,
    BackoffSchedule,
    RotationPolicy,
    detect_429,
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
