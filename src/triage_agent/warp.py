"""WarpManager: drive the Cloudflare WARP userspace daemon through warp-cli.

``warp-cli`` talks to ``warp-svc``, which normally runs under systemd.  In
the job container there is no systemd, so the entrypoint starts ``warp-svc``
manually and this manager only ever issues CLI commands.

Every public method returns :class:`WarpResult` ``(ok, detail)`` and never
raises: a warp failure must fail the current job, not the dispatcher loop.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass

DEFAULT_CLI = "warp-cli"
DEFAULT_COMMAND_TIMEOUT = 30.0
DEFAULT_WAIT_POLL = 2.0
ACCEPT_TERMS_FLAG = "--accept-terms"


class WarpError(RuntimeError):
    """A warp-cli invocation failed (missing binary, timeout, bad exit)."""


@dataclass(frozen=True)
class WarpResult:
    ok: bool
    detail: str


class WarpManager:
    """Wrap the warp-cli binary; all commands run with timeouts."""

    def __init__(
        self,
        cli: str | None = None,
        *,
        command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
        runner: object = subprocess.run,
    ) -> None:
        name = (cli or os.environ.get("WARP_CLI", "")).strip() or DEFAULT_CLI
        resolved = shutil.which(name)
        if resolved is None:
            raise WarpError(f"warp-cli binary not found on PATH: {name!r}")
        self.cli = resolved
        self.command_timeout = command_timeout
        self._runner = runner

    def _run(self, args: list[str], timeout: float | None = None) -> str:
        proc = self._runner(
            [self.cli, *args],
            capture_output=True,
            text=True,
            timeout=timeout or self.command_timeout,
        )
        if proc.returncode != 0:
            raise WarpError(
                f"warp-cli {' '.join(args)} exited {proc.returncode}:"
                f" {proc.stderr.strip()[:256]}"
            )
        return proc.stdout

    def _attempt(self, args: list[str]) -> WarpResult:
        try:
            out = self._run(args)
        except (WarpError, subprocess.TimeoutExpired, OSError) as exc:
            return WarpResult(False, str(exc))
        return WarpResult(True, out.strip())

    def status(self) -> tuple[bool, dict]:
        """Parse ``warp-cli status`` into a dict. Never raises."""

        try:
            out = self._run(["status"])
        except (WarpError, subprocess.TimeoutExpired, OSError) as exc:
            return False, {"error": str(exc)}
        parsed: dict[str, str] = {}
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            parsed[key.strip().lower().replace(" ", "_")] = value.strip()
        return True, parsed

    def is_connected(self) -> bool:
        ok, parsed = self.status()
        if not ok:
            return False
        state = parsed.get("status", "").lower()
        return state == "connected"

    def connect(self) -> WarpResult:
        return self._attempt(["connect"])

    def disconnect(self) -> WarpResult:
        return self._attempt(["disconnect"])

    def delete_registration(self) -> WarpResult:
        return self._attempt(["registration", "delete"])

    def ensure_connected(self) -> WarpResult:
        """Connect, registering non-interactively first when needed."""

        if self.is_connected():
            return WarpResult(True, "already connected")
        reg = self._attempt(["registration", "new", ACCEPT_TERMS_FLAG])
        if not reg.ok and ACCEPT_TERMS_FLAG in reg.detail:
            reg = self._attempt(["registration", "new"])
        if not reg.ok and "registration" not in reg.detail.lower():
            return reg
        return self.connect()

    def wait_connected(self, timeout: float) -> WarpResult:
        """Poll status until connected or the deadline passes."""

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_connected():
                return WarpResult(True, "connected")
            time.sleep(DEFAULT_WAIT_POLL)
        ok, parsed = self.status()
        state = parsed.get("status", "unknown") if ok else parsed.get("error")
        return WarpResult(False, f"not connected after {timeout}s: {state}")

    def rotate(self) -> WarpResult:
        """Delete the registration, register fresh, reconnect."""

        for step in (
            self.delete_registration,
            lambda: self._attempt(["registration", "new", ACCEPT_TERMS_FLAG]),
            self.connect,
        ):
            result = step()
            if not result.ok:
                return result
        return self.wait_connected(self.command_timeout * 2)

    def __enter__(self) -> WarpManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()
