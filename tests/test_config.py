import pytest

from triage_agent.config import ConfigError, Settings, WarpSettings


def test_defaults_from_empty_env():
    s = Settings.from_env({})
    assert s.feed_url == "https://watcher.trustsight.org"
    assert s.poll_interval_seconds == 120
    assert s.github_token is None
    assert s.feed_key is None
    assert s.warp.enable_rotation is True
    assert s.warp.max_rotations == 5
    assert s.model == "opencode/mimo-v2.6-flash-free"
    assert s.warp.backoff_min_seconds == 30.0
    assert s.warp.backoff_max_seconds == 900.0
    assert s.warp.backoff_factor == 2.0
    assert s.warp.backoff_jitter == 0.25


def test_warp_schedule_matches_rate_limit_defaults():
    from triage_agent.rate_limit import BackoffSchedule

    s = Settings.from_env({})
    schedule = s.warp.schedule()
    assert schedule.minimum == 30.0
    assert schedule.maximum == 900.0
    assert schedule.factor == 2.0
    assert schedule.jitter == 0.25
    reference = BackoffSchedule(rng=lambda: 0.0)
    pinned = s.warp.schedule()
    pinned._rng = lambda: 0.0
    assert pinned.next_delay(2) == reference.next_delay(2)


def test_env_overrides():
    s = Settings.from_env(
        {
            "TRUSTSIGHT_FEED_URL": "https://feed.example.org",
            "TRIAGE_POLL_INTERVAL_SECONDS": "30",
            "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x",
            "TRUSTSIGHT_FEED_KEY": "k",
            "TRUSTSIGHT_NTFY_WEBHOOK": "https://ntfy.example.org/ws",
            "TRIAGE_WARP_MAX_ROTATIONS": "3",
            "TRIAGE_WARP_BACKOFF_MIN": "1.0",
            "TRIAGE_WARP_BACKOFF_MAX": "10.0",
        }
    )
    assert s.feed_url == "https://feed.example.org"
    assert s.poll_interval_seconds == 30
    assert s.github_token == "ghp_x"
    assert s.warp.max_rotations == 3
    assert s.warp.backoff_max_seconds == 10.0


def test_bad_poll_interval_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"TRIAGE_POLL_INTERVAL_SECONDS": "0"})
    with pytest.raises(ConfigError):
        Settings.from_env({"TRIAGE_POLL_INTERVAL_SECONDS": "abc"})


def test_bad_feed_url_rejected():
    with pytest.raises(ConfigError):
        Settings(feed_url="ftp://example.org")


def test_warp_bounds_validated():
    with pytest.raises(ConfigError):
        WarpSettings(backoff_min_seconds=30.0, backoff_max_seconds=5.0)
    with pytest.raises(ConfigError):
        WarpSettings(max_rotations=0)
    with pytest.raises(ConfigError):
        WarpSettings(backoff_factor=0.5)
    with pytest.raises(ConfigError):
        WarpSettings(backoff_jitter=1.5)


def test_warp_env_overrides():
    s = Settings.from_env(
        {
            "TRIAGE_WARP_BACKOFF_FACTOR": "3.0",
            "TRIAGE_WARP_BACKOFF_JITTER": "0.1",
        }
    )
    assert s.warp.backoff_factor == 3.0
    assert s.warp.backoff_jitter == 0.1
    with pytest.raises(ConfigError):
        Settings.from_env({"TRIAGE_WARP_BACKOFF_FACTOR": "0.5"})


def test_job_secrets_enforced():
    s = Settings.from_env({})
    with pytest.raises(ConfigError) as exc:
        s.require_job_secrets()
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in str(exc.value)
    with pytest.raises(ConfigError) as exc:
        Settings.from_env(
            {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x"}
        ).require_job_secrets()
    assert "OPENCODE_API_KEY" in str(exc.value)
    ok = Settings.from_env(
        {
            "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x",
            "OPENCODE_API_KEY": "oc_x",
        }
    )
    ok.require_job_secrets()  # feed key is optional; the feed sink is skipped
    # Non-zen profiles do not require the Zen key.
    Settings.from_env(
        {
            "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x",
            "TRIAGE_MODEL_PROFILE": "openai-compatible",
            "TRIAGE_MODEL_BASE_URL": "http://localhost:11434/v1",
            "TRIAGE_MODEL_NAME": "qwen2.5-coder",
        }
    ).require_job_secrets()


def test_docker_host_from_env():
    s = Settings.from_env({"TRIAGE_DOCKER_HOST": "unix:///var/run/docker.sock"})
    assert s.docker_host == "unix:///var/run/docker.sock"
    s = Settings.from_env({})
    assert s.docker_host is None
