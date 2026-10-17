"""Verdict validation and job orchestration.

``validate_verdict`` strictly checks a verdict dict (or its JSON file)
against the schema, mirroring the harness fp_agent caps: total document at
most 1 MiB, strings at most 4096 chars, package names matching the AUR-safe
regex. ``run_job`` then verifies the verdict through the harness CLI
(``harness fp_agent_verify``); the actual agent execution happens behind the
``RunnerBackend`` protocol, with a local stub backend for tests until the
container backend lands.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

MAX_VERDICT_BYTES = 1 << 20  # 1 MiB
MAX_STRING = 4096
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,254}$")

VERDICTS = ("FP", "TP", "uncertain")
CONFIDENCES = ("high", "medium", "low")

_TOP_KEYS = {
    "schema_version",
    "package",
    "verdict",
    "confidence",
    "rationale",
    "evidence",
    "proposed_changes",
    # Optional keys the harness verifier consumes (findings for FP replay,
    # ioc_entries for TP); the agent may or may not include them.
    "alert_slug",
    "version_transition",
    "findings",
    "ioc_entries",
}


class VerdictError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _check_string(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise VerdictError(f"{where} must be a string")
    if len(value) > MAX_STRING:
        raise VerdictError(f"{where} exceeds {MAX_STRING} chars")
    return value


def validate_verdict(doc: object, *, max_bytes: int = MAX_VERDICT_BYTES) -> dict:
    """Strictly validate a parsed verdict document. Raises VerdictError."""

    raw = json.dumps(doc, sort_keys=True)
    if len(raw.encode("utf-8")) > max_bytes:
        raise VerdictError(f"verdict exceeds {max_bytes} bytes")
    if not isinstance(doc, dict):
        raise VerdictError("verdict must be a JSON object")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        raise VerdictError(f"unknown keys: {sorted(unknown)}")
    missing = {"schema_version", "package", "verdict", "confidence"} - set(doc)
    if missing:
        raise VerdictError(f"missing keys: {sorted(missing)}")
    if doc["schema_version"] != 1:
        raise VerdictError("schema_version must be 1")
    package = _check_string(doc["package"], "package")
    if not _PACKAGE_RE.match(package):
        raise VerdictError(f"invalid package name: {package!r}")
    if doc["verdict"] not in VERDICTS:
        raise VerdictError(f"verdict must be one of {VERDICTS}")
    if doc["confidence"] not in CONFIDENCES:
        raise VerdictError(f"confidence must be one of {CONFIDENCES}")
    if "rationale" in doc:
        _check_string(doc["rationale"], "rationale")
    for key in ("evidence", "proposed_changes"):
        if key in doc and not isinstance(doc[key], dict):
            raise VerdictError(f"{key} must be an object")
    for key in ("findings", "ioc_entries"):
        if key in doc and not isinstance(doc[key], list):
            raise VerdictError(f"{key} must be a list")

    def walk(value: object, where: str) -> None:
        if isinstance(value, str):
            _check_string(value, where)
        elif isinstance(value, dict):
            for k, v in value.items():
                _check_string(k, f"{where} key")
                walk(v, f"{where}.{k}")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{where}[{i}]")

    for key in ("evidence", "proposed_changes", "findings", "ioc_entries"):
        if key in doc:
            walk(doc[key], key)
    return doc


def load_verdict(path: str | Path) -> dict:
    """Read and validate a verdict.json file (no symlink following)."""

    p = Path(path)
    if p.is_symlink():
        raise VerdictError(f"verdict path is a symlink: {p}")
    data = p.read_bytes()
    if len(data) > MAX_VERDICT_BYTES:
        raise VerdictError(f"verdict file exceeds {MAX_VERDICT_BYTES} bytes")
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as exc:
        raise VerdictError(f"verdict is not valid JSON: {exc}") from exc
    return validate_verdict(doc)


@dataclass(frozen=True)
class RunOutcome:
    outcome: str  # "verified" | "needs_review" | "failed"
    verdict: dict | None = None
    verify_result: dict | None = None
    reason: str | None = None


class RunnerBackend(Protocol):
    """How the agent actually executes. The container backend comes later."""

    def run(self, *, prompt: str, job_id: str, job_root: str) -> Path:
        """Run the agent for one job; return the verdict.json path it wrote."""
        ...


class LocalStubBackend:
    """Test/dev backend: writes a canned verdict file immediately."""

    def __init__(self, verdict: dict | None = None):
        self._verdict = verdict or {
            "schema_version": 1,
            "package": "example-pkg",
            "verdict": "FP",
            "confidence": "high",
            "rationale": "stub",
            "evidence": {},
            "proposed_changes": {},
        }
        self.calls: list[dict] = []

    def run(self, *, prompt: str, job_id: str, job_root: str) -> Path:
        from .queue import write_job_file

        self.calls.append({"prompt": prompt, "job_id": job_id})
        data = json.dumps(self._verdict, indent=2).encode()
        return write_job_file(job_root, job_id, "verdict.json", data)


def harness_verify(
    verdict: dict,
    *,
    cli: str = "harness",
    timeout: int = 900,
) -> dict:
    """Verify a verdict via `harness fp_agent_verify --verdict <file>`.

    The verdict travels as a temp file, not argv (verdicts are capped at
    1 MiB) and not stdin (the harness CLI reads flags, not stdin).
    """

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", encoding="utf-8", delete=False
    ) as handle:
        json.dump(verdict, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [cli, "fp_agent_verify", "--verdict", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        raise RuntimeError(
            f"harness fp_agent_verify exited {proc.returncode}:"
            f" {proc.stderr.strip()[:512]}"
        )
    return json.loads(proc.stdout)


def run_job(
    *,
    job_id: str,
    prompt: str,
    job_root: str,
    backend: RunnerBackend,
    cli: str = "harness",
    timeout: int = 900,
    verify: object = harness_verify,
) -> RunOutcome:
    """Orchestrate one job: run agent, validate verdict, verify via harness."""

    try:
        verdict_path = backend.run(prompt=prompt, job_id=job_id, job_root=job_root)
    except Exception as exc:
        return RunOutcome(outcome="failed", reason=f"backend: {exc}")
    try:
        verdict = load_verdict(verdict_path)
    except VerdictError as exc:
        return RunOutcome(outcome="failed", reason=f"invalid verdict: {exc.reason}")
    if verdict["verdict"] == "uncertain" or verdict["confidence"] == "low":
        return RunOutcome(outcome="needs_review", verdict=verdict)
    try:
        result = verify(verdict, cli=cli, timeout=timeout)
    except Exception as exc:
        return RunOutcome(outcome="failed", verdict=verdict, reason=f"verify: {exc}")
    if isinstance(result, dict) and result.get("verified") is False:
        reason = result.get("reason") or "harness cross-check did not verify"
        return RunOutcome(
            outcome="failed", verdict=verdict,
            reason=f"verify: unverified: {reason}",
        )
    return RunOutcome(outcome="verified", verdict=verdict, verify_result=result)
