"""warp.py against a fake warp-cli shell script placed on PATH."""

from __future__ import annotations

import os

import pytest

from triage_agent import warp

FAKE_SCRIPT = """#!/bin/sh
echo "$*" >> "$WARP_FAKE_LOG"
case "$WARP_FAKE_MODE" in
  connected)
    case "$1" in
      status) echo "Status: Connected" ;;
      *) echo "Success" ;;
    esac
    ;;
  disconnected)
    case "$1" in
      status) echo "Status: Disconnected" ;;
      registration) echo "registration failed" >&2; exit 1 ;;
      connect) echo "connect failed" >&2; exit 1 ;;
      *) echo "Success" ;;
    esac
    ;;
  flaky)
    case "$1" in
      status)
        if [ -f "$WARP_FAKE_CONNECTED_ONCE" ]; then
          echo "Status: Connected"
        else
          touch "$WARP_FAKE_CONNECTED_ONCE"
          echo "Status: Disconnected"
        fi
        ;;
      *) echo "Success" ;;
    esac
    ;;
  slow-connect)
    case "$1" in
      status) echo "Status: Disconnected" ;;
      connect) sleep 60 ;;
      *) echo "Success" ;;
    esac
    ;;
esac
exit 0
"""


@pytest.fixture()
def warp_env(tmp_path, monkeypatch):
    script = tmp_path / "warp-cli"
    script.write_text(FAKE_SCRIPT)
    script.chmod(0o755)
    monkeypatch.setenv("WARP_CLI", "warp-cli")
    monkeypatch.setenv("WARP_FAKE_LOG", str(tmp_path / "calls.log"))
    monkeypatch.setenv("WARP_FAKE_CONNECTED_ONCE", str(tmp_path / "once"))
    monkeypatch.setenv("WARP_FAKE_MODE", "connected")
    monkeypatch.setenv(
        "PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    return tmp_path


def _calls(tmp_path) -> list[list[str]]:
    log = tmp_path / "calls.log"
    if not log.exists():
        return []
    return [line.split() for line in log.read_text().splitlines()]


def test_missing_binary_raises(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("WARP_CLI", "warp-cli")
    with pytest.raises(warp.WarpError, match="not found"):
        warp.WarpManager()


def test_status_parsed_connected(warp_env):
    manager = warp.WarpManager()
    ok, parsed = manager.status()
    assert ok
    assert parsed["status"] == "Connected"
    assert manager.is_connected()


def test_ensure_connected_noop_when_connected(warp_env):
    manager = warp.WarpManager()
    result = manager.ensure_connected()
    assert result.ok
    assert _calls(warp_env) == [["status"]]


def test_rotate_invokes_delete_new_connect(warp_env):
    manager = warp.WarpManager(command_timeout=5.0)
    result = manager.rotate()
    assert result.ok
    calls = _calls(warp_env)
    assert ["registration", "delete"] in calls
    assert ["registration", "new", "--accept-terms"] in calls
    assert ["connect"] in calls


def test_connect_failure_returns_not_raises(warp_env, monkeypatch):
    monkeypatch.setenv("WARP_FAKE_MODE", "disconnected")
    manager = warp.WarpManager()
    result = manager.ensure_connected()
    assert not result.ok
    assert manager.is_connected() is False


def test_wait_connected_timeout(warp_env, monkeypatch):
    monkeypatch.setenv("WARP_FAKE_MODE", "slow-connect")
    manager = warp.WarpManager(command_timeout=0.2)
    result = manager.wait_connected(timeout=0.3)
    assert not result.ok


def test_wait_connected_eventually(warp_env, monkeypatch):
    monkeypatch.setenv("WARP_FAKE_MODE", "flaky")
    manager = warp.WarpManager()
    result = manager.wait_connected(timeout=10.0)
    assert result.ok


def test_slow_command_times_out(warp_env, monkeypatch):
    monkeypatch.setenv("WARP_FAKE_MODE", "slow-connect")
    manager = warp.WarpManager(command_timeout=0.2)
    result = manager.connect()
    assert not result.ok
    assert "timed out" in result.detail.lower() or "Timeout" in result.detail


def test_context_manager_disconnects(warp_env):
    with warp.WarpManager() as manager:
        assert manager.is_connected()
    assert ["disconnect"] in _calls(warp_env)
