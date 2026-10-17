"""DockerBackend: run one triage job as a hardened, single-use container.

Implements the :class:`triage_agent.runner.RunnerBackend` protocol by
shelling out to the docker CLI (the same subprocess convention as
``runner.harness_verify`` and ``pr_backstop.harness_render_pr``; the
``docker`` Python SDK is deliberately not a dependency). One container per
job, per rotation attempt:

- the image is ``TRIAGE_IMAGE`` (default ``trustsight-triage-agent:live``);
- the job runs on a per-job docker volume mounted at ``/job`` so no host
  path is ever exposed to the agent;
- the prompt is bind-mounted read-only at ``/job/prompt.txt``;
- runtime flags mirror ``docker-compose.yml``: read-only rootfs, tmpfs
  ``/tmp`` and ``/var/lib/cloudflare-warp`` (fresh WARP registration per
  container, which is exactly the rotation model), all capabilities
  dropped, ``NET_ADMIN`` re-added only when warp rotation is on, plus
  ``/dev/net/tun`` and a ``/run`` tmpfs for the warp daemon,
  ``no-new-privileges``. There is deliberately no ``-u``: the container
  starts as root and the entrypoint bootstraps warp-svc plus a writable
  ``$HOME``, then setpriv-drops to the non-root ``triage`` user before
  exec'ing the job, so the job never runs as root. ``--network none``
  unless ``TRIAGE_DOCKER_NETWORK`` names a pre-configured restricted
  network, plus memory/CPU limits;
- secrets pass via bare ``-e NAME`` flags (docker reads the values from
  the worker's own environment), so the token never appears in argv, in
  ``ps``, or in logs.

Container output is capped (10 MiB) and recorded under the job dir as
``container.log``. A nonzero exit fails the job with the log tail as the
reason, except when the output signals rate limiting: the
:class:`~triage_agent.rate_limit.RotationPolicy` budget is then spent by
re-running in fresh containers, followed by one fallback-model run, and
only then the job fails.

On success the verdict is copied out of the volume to
``<job_root>/<job_id>/verdict.json`` (via the symlink-safe
:func:`triage_agent.queue.write_job_file`) and its path returned; a
``/job/pr_url`` artifact is exposed as ``last_pr_url`` for the pipeline's
backstop fast path. When absent, the backstop discovers the PR by branch.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from . import rate_limit
from .queue import write_job_file

log = logging.getLogger(__name__)

MAX_LOG_BYTES = 10 << 20
REASON_TAIL_BYTES = 4096
FALLBACK_MODEL = "opencode/glm-5.3-flash-free"

#: argv the backend runs inside the container (triage-agent agent-job).
CONTAINER_CMD = ("triage-agent", "agent-job")


class DockerJobError(RuntimeError):
    """The container run failed; ``str()`` is the job failure reason."""


class _ModelOverride:
    """Shallow settings proxy overriding ``model`` for the fallback run."""

    def __init__(self, settings: object, model: str):
        object.__setattr__(self, "_settings", settings)
        object.__setattr__(self, "_model", model)

    def __getattr__(self, name: str):
        if name == "model":
            return object.__getattribute__(self, "_model")
        return getattr(object.__getattribute__(self, "_settings"), name)


class DockerBackend:
    """RunnerBackend over ``docker run``; see the module docstring."""

    def __init__(
        self,
        settings: object,
        *,
        docker: str = "docker",
        runner: object = subprocess.run,
    ) -> None:
        self.settings = settings
        self.docker = docker
        self._runner = runner
        self.image = getattr(settings, "triage_image",
                             "trustsight-triage-agent:live")
        self.network = getattr(settings, "docker_network", None)
        self.memory_mb = getattr(settings, "docker_memory_mb", None)
        self.cpus = getattr(settings, "docker_cpus", None)
        self.timeout = getattr(settings, "job_timeout_seconds", 3600)
        warp = getattr(settings, "warp", None)
        self.max_rotations = getattr(warp, "max_rotations", 5)
        self.last_pr_url: str | None = None

    # -- docker CLI plumbing ---------------------------------------------

    def _docker(self, args: list[str], *, timeout: float | None = None):
        try:
            return self._runner(
                [self.docker, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except OSError as exc:
            raise DockerJobError(f"docker CLI failed: {exc}") from exc

    def _warp_enabled(self) -> bool:
        warp = getattr(self.settings, "warp", None)
        return bool(getattr(warp, "enable_rotation", False))

    def _run_flags(self, container: str, volume: str,
                   prompt_path: Path) -> list[str]:
        flags = [
            "run",
            "--name", container,
            "--read-only",
            "--tmpfs", "/tmp",
            "--tmpfs", "/var/lib/cloudflare-warp",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "-e", "HOME=/tmp/home",  # bun/opencode writes under $HOME
            "-v", f"{volume}:/job",
            "-v", f"{prompt_path}:/job/prompt.txt:ro",
            "--network", self.network or "none",
        ]
        # No -u: the container starts as root for the entrypoint's
        # warp/HOME bootstrap and setpriv-drops to the triage user
        # before exec'ing the job (docker/entrypoint.sh). The bootstrap
        # needs these specific caps; the setpriv drop clears them for
        # the job process.
        flags += ["--cap-add", "CHOWN",
                  "--cap-add", "SETUID",
                  "--cap-add", "SETGID"]
        if self._warp_enabled():
            # warp-svc needs the TUN device and a writable /run for its
            # socket; both are root-bootstrap concerns (the entrypoint
            # drops to the job user before the agent starts).
            flags += ["--cap-add", "NET_ADMIN",
                      "--device", "/dev/net/tun",
                      "--tmpfs", "/run"]
        if self.memory_mb:
            flags += ["--memory", f"{self.memory_mb}m"]
        if self.cpus:
            flags += ["--cpus", str(self.cpus)]
        flags += self._env_flags()
        return flags

    def _env_flags(self) -> list[str]:
        """Env into the container; secrets use bare -e NAME (no values)."""

        flags: list[str] = []
        # Bare name only: docker copies the value from the worker process
        # environment, so the token never shows up in argv or ps output.
        flags += ["-e", "GITHUB_PERSONAL_ACCESS_TOKEN"]
        # opencode Zen route key; bare name, never a value.
        flags += ["-e", "OPENCODE_API_KEY"]
        feed_url = getattr(self.settings, "feed_url", None)
        if feed_url:
            flags += ["-e", f"TRUSTSIGHT_FEED_URL={feed_url}"]
        model = getattr(self.settings, "model", None)
        if model:
            flags += ["-e", f"TRIAGE_MODEL={model}"]
        flags += [
            "-e",
            f"ENABLE_WARP_ROTATION={'1' if self._warp_enabled() else '0'}",
        ]
        return flags

    # -- one container attempt ---------------------------------------------

    def _run_container(self, container: str, volume: str,
                       prompt_path: Path) -> tuple[str, int]:
        flags = self._run_flags(container, volume, prompt_path)
        try:
            proc = self._docker(
                [*flags, self.image, *CONTAINER_CMD],
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            self._kill_container(container)
            raise DockerJobError(
                f"container timed out after {self.timeout}s"
            ) from None
        output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[
            -MAX_LOG_BYTES:
        ]
        return output, proc.returncode

    def _kill_container(self, container: str) -> None:
        try:
            self._docker(["rm", "-f", container], timeout=30)
        except DockerJobError:
            log.warning("could not remove timed-out container %s", container)

    def _read_from_volume(self, volume: str, name: str) -> str | None:
        """cat one file out of the job volume via a throwaway container."""

        proc = self._docker(
            [
                "run", "--rm",
                "-v", f"{volume}:/job:ro",
                "--entrypoint", "/bin/cat",
                self.image,
                f"/job/{name}",
            ],
            timeout=60,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout

    # -- RunnerBackend ------------------------------------------------------

    def run(self, *, prompt: str, job_id: str, job_root: str) -> Path:
        """Run the job container to completion; return the local verdict path.

        Raises :class:`DockerJobError` (never anything else) on failure.
        """

        self.last_pr_url = None
        original_settings = self.settings
        prompt_path = write_job_file(
            job_root, job_id, "prompt.txt", prompt.encode("utf-8")
        )
        policy = rate_limit.RotationPolicy(self.max_rotations)
        rotations_used = 0
        fallback_used = False
        attempt = 0
        try:
            while True:
                attempt += 1
                container = f"triage-{job_id[:12]}-{attempt}"
                volume = f"triage-job-{job_id[:12]}-{attempt}"
                self._docker(["volume", "create", volume])
                try:
                    output, rc = self._run_container(container, volume,
                                                     prompt_path)
                    self._record_log(job_root, job_id, attempt, output)
                    if rc == 0:
                        return self._collect(job_root, job_id, volume)

                    # The agent job exits 3 to signal rate limiting without
                    # the backend having to pattern-match the log.
                    limited = rc == 3 or rate_limit.detect_429(output)
                    decision = policy.decide(
                        rate_limited=limited, rotations_used=rotations_used
                    )
                    log.warning(
                        "job %s attempt %d failed (rc=%d,"
                        " rate_limited=%s): %s",
                        job_id, attempt, rc, limited, decision.detail,
                    )
                    if decision.action == "rotate":
                        # A fresh container is a fresh tmpfs, so WARP
                        # registers an anonymous consumer from scratch:
                        # that is the egress rotation; no warp-cli is
                        # needed out here.
                        rotations_used += 1
                        continue
                    if decision.action == "fallback_model":
                        if fallback_used:
                            raise DockerJobError(
                                "rate limited through the rotation budget"
                                " and the fallback model run:"
                                f" {output.strip()[-REASON_TAIL_BYTES:]}"
                            )
                        fallback_used = True
                        self.settings = _ModelOverride(
                            original_settings, FALLBACK_MODEL
                        )
                        continue
                    raise DockerJobError(
                        f"container exited {rc}:"
                        f" {output.strip()[-REASON_TAIL_BYTES:]}"
                    )
                finally:
                    self._docker(["volume", "rm", "-f", volume])
        finally:
            self.settings = original_settings

    def _record_log(self, job_root: str, job_id: str, attempt: int,
                    output: str) -> None:
        job_dir = Path(job_root) / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        name = "container.log" if attempt == 1 else f"container-{attempt}.log"
        (job_dir / name).write_bytes(
            output.encode("utf-8", "replace")[-MAX_LOG_BYTES:]
        )

    def _collect(self, job_root: str, job_id: str, volume: str) -> Path:
        """Copy the verdict (and optional pr_url) out of the job volume."""

        raw = self._read_from_volume(volume, "verdict.json")
        if raw is None:
            raise DockerJobError(
                "container exited 0 but wrote no /job/verdict.json"
            )
        verdict_path = write_job_file(
            job_root, job_id, "verdict.json", raw.encode("utf-8")
        )
        pr_url = self._read_from_volume(volume, "pr_url")
        if pr_url:
            self.last_pr_url = pr_url.strip().splitlines()[-1] or None
        agent_output = self._read_from_volume(volume, "agent-output.txt")
        if agent_output:
            write_job_file(
                job_root, job_id, "agent-output.txt",
                agent_output.encode("utf-8")[-MAX_LOG_BYTES:],
            )
        return verdict_path
