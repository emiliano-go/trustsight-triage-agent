"""DockerBackend against a fake docker CLI (no real containers)."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from triage_agent.config import Settings, WarpSettings
from triage_agent.docker_backend import DockerBackend, DockerJobError

VERDICT = {
    "schema_version": 1,
    "package": "hello-aur",
    "verdict": "FP",
    "confidence": "high",
    "rationale": "stub",
    "evidence": {},
    "proposed_changes": {},
}


class FakeDocker:
    """Emulates the docker CLI: volumes, container runs, cat helper."""

    def __init__(self, tmp_path, mode="ok", pr_url=None, fail_output="boom"):
        self.tmp_path = tmp_path
        self.mode = mode
        self.pr_url = pr_url
        self.fail_output = fail_output
        self.volumes: dict[str, dict[str, str]] = {}
        self.calls: list[list[str]] = []
        self.attempts = 0

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[1] == "volume":
            if cmd[2] == "create":
                self.volumes[cmd[3]] = {}
            else:
                self.volumes.pop(cmd[-1], None)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if cmd[1] == "rm":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "--entrypoint" in cmd:
            vol = self._volume_of(cmd, ":/job:ro")
            content = self.volumes.get(vol, {}).get(cmd[-1])
            if content is None:
                return SimpleNamespace(returncode=1, stdout="",
                                       stderr="No such file")
            return SimpleNamespace(returncode=0, stdout=content, stderr="")
        # the job container itself
        self.attempts += 1
        vol = self._volume_of(cmd, ":/job")
        prompt = self._volume_of(cmd, ":/job/prompt.txt:ro")
        self.volumes[vol]["prompt.txt"] = Path(prompt).read_text()
        if self.mode == "429_then_ok":
            mode = "429_always" if self.attempts == 1 else "ok"
        elif self.mode == "exit3_then_ok":
            if self.attempts == 1:
                return SimpleNamespace(
                    returncode=3, stdout="",
                    stderr="agent-job: rate limited; no 429 text here",
                )
            mode = "ok"
        else:
            mode = self.mode
        if mode in ("ok", "429_then_ok"):
            self.volumes[vol]["/job/verdict.json"] = json.dumps(VERDICT)
            if self.pr_url:
                self.volumes[vol]["/job/pr_url"] = self.pr_url + "\n"
            return SimpleNamespace(returncode=0, stdout="agent ran",
                                   stderr="")
        if mode == "noverdict":
            return SimpleNamespace(returncode=0, stdout="nothing", stderr="")
        if mode == "429_always":
            return SimpleNamespace(
                returncode=1, stdout="",
                stderr='{"message": "429 Too Many Requests"}',
            )
        return SimpleNamespace(returncode=1, stdout="",
                               stderr=self.fail_output)

    @staticmethod
    def _volume_of(cmd, suffix):
        return next(a[: -len(suffix)] for a in cmd if a.endswith(suffix))


def make_settings(**over):
    warp = WarpSettings(enable_rotation=over.pop("warp_rotation", False))
    return Settings(warp=warp, **over)


def make_backend(tmp_path, settings=None, **fake_kwargs):
    fake = FakeDocker(tmp_path, **fake_kwargs)
    # No real sleeping in tests: pacing delays are recorded, not endured.
    backend = DockerBackend(
        settings or make_settings(), runner=fake, sleeper=lambda _s: None
    )
    return backend, fake


def run_kwargs(tmp_path):
    return {
        "prompt": "do the triage",
        "job_id": "abc123def456",
        "job_root": str(tmp_path / "jobs"),
    }


def test_run_success_collects_verdict_and_pr_url(tmp_path):
    backend, fake = make_backend(
        tmp_path, pr_url="https://github.com/acme/trustsight/pull/7"
    )
    path = backend.run(**run_kwargs(tmp_path))
    assert json.loads(Path(path).read_text()) == VERDICT
    assert backend.last_pr_url == "https://github.com/acme/trustsight/pull/7"
    # logs recorded, container.log exists under the job dir
    assert (tmp_path / "jobs" / "abc123def456" / "container.log").exists()
    assert "agent ran" in (
        tmp_path / "jobs" / "abc123def456" / "container.log"
    ).read_text()


def test_hardening_flags_and_none_network(tmp_path):
    backend, fake = make_backend(tmp_path)
    backend.run(**run_kwargs(tmp_path))
    flags = next(c for c in fake.calls if c[1] == "run"
                 and "--entrypoint" not in c)
    joined = " ".join(flags)
    for expected in (
        "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true",
        "--network none", "--tmpfs /tmp",
        "--tmpfs /var/lib/cloudflare-warp", "agent-job",
    ):
        assert expected in joined
    # Privilege dropping is entrypoint-owned (root bootstrap, setpriv drop
    # to triage); the backend must not pin the container user.
    assert "-u" not in flags
    assert "--user" not in flags
    assert "--cap-add NET_ADMIN" not in joined


def test_warp_and_network_and_limits_flags(tmp_path):
    settings = make_settings(
        warp_rotation=True, docker_network="triage-egress",
        docker_memory_mb=2048, docker_cpus=1.5,
    )
    backend, fake = make_backend(tmp_path, settings=settings)
    backend.run(**run_kwargs(tmp_path))
    flags = next(c for c in fake.calls if c[1] == "run"
                 and "--entrypoint" not in c)
    joined = " ".join(flags)
    assert "--cap-add NET_ADMIN" in joined
    assert "--device /dev/net/tun" in joined
    assert "--tmpfs /run" in joined
    assert "--network triage-egress" in joined
    assert "--memory 2048m" in joined
    assert "--cpus 1.5" in joined


def test_warp_off_omits_warp_only_flags(tmp_path):
    settings = make_settings(warp_rotation=False)
    backend, fake = make_backend(tmp_path, settings=settings)
    backend.run(**run_kwargs(tmp_path))
    flags = next(c for c in fake.calls if c[1] == "run"
                 and "--entrypoint" not in c)
    joined = " ".join(flags)
    assert "--cap-add NET_ADMIN" not in joined
    assert "--device /dev/net/tun" not in joined
    assert "--tmpfs /run" not in joined


def test_token_never_appears_in_docker_argv(tmp_path):
    settings = make_settings()
    backend, fake = make_backend(tmp_path, settings=settings)
    backend.run(**run_kwargs(tmp_path))
    argv = "\n".join(" ".join(c) for c in fake.calls)
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in argv  # bare -e flag
    assert "ghp_" not in argv


def test_nonzero_exit_fails_with_tail(tmp_path):
    backend, _ = make_backend(tmp_path, mode="fail", fail_output="x" * 9000)
    with pytest.raises(DockerJobError) as excinfo:
        backend.run(**run_kwargs(tmp_path))
    assert "boom" not in str(excinfo.value)  # tail only, capped
    assert "x" * 500 in str(excinfo.value)


def test_429_rotates_then_succeeds(tmp_path):
    backend, fake = make_backend(tmp_path, mode="429_then_ok")
    path = backend.run(**run_kwargs(tmp_path))
    assert fake.attempts == 2
    assert json.loads(Path(path).read_text()) == VERDICT
    # each attempt is a fresh volume: that is the WARP rotation
    assert len([c for c in fake.calls if c[1:3] == ["volume", "create"]]) == 2


def test_exit_code_3_rotates_even_without_429_text(tmp_path):
    """agent-job exit 3 is the rotation signal; the backend must not
    need to pattern-match rate-limit text in the container output."""
    backend, fake = make_backend(tmp_path, mode="exit3_then_ok")
    path = backend.run(**run_kwargs(tmp_path))
    assert fake.attempts == 2
    assert json.loads(Path(path).read_text()) == VERDICT


def test_429_always_exhausts_rotations_then_fallback(tmp_path):
    backend, fake = make_backend(tmp_path, mode="429_always")
    with pytest.raises(DockerJobError) as excinfo:
        backend.run(**run_kwargs(tmp_path))
    # 5 rotation reruns + 1 fallback-model run; the failure of the fallback
    # run is what surfaces (no seventh container).
    assert fake.attempts == 7
    assert "fallback" in str(excinfo.value)


def test_missing_verdict_fails(tmp_path):
    backend, _ = make_backend(tmp_path, mode="noverdict")
    with pytest.raises(DockerJobError, match="verdict.json"):
        backend.run(**run_kwargs(tmp_path))


def test_timeout_kills_container(tmp_path):
    class SlowDocker(FakeDocker):
        def __call__(self, cmd, **kwargs):
            if cmd[1] == "run" and "--entrypoint" not in cmd:
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            return super().__call__(cmd, **kwargs)

    fake = SlowDocker(tmp_path)
    backend = DockerBackend(make_settings(), runner=fake)
    backend.timeout = 5
    with pytest.raises(DockerJobError, match="timed out"):
        backend.run(**run_kwargs(tmp_path))
    assert any(c[1:3] == ["rm", "-f"] for c in fake.calls)


def test_docker_cli_missing_fails_cleanly(tmp_path):
    def missing(cmd, **kwargs):
        raise OSError(2, "No such file or directory")

    backend = DockerBackend(make_settings(), runner=missing)
    with pytest.raises(DockerJobError, match="docker CLI"):
        backend.run(**run_kwargs(tmp_path))
