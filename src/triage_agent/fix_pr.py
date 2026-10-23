"""Ship an FP verdict's code fixes as a real PR from a working clone.

The agent proposes fixes as unified diffs in its verdict (it has no file
write tool). This module is the deterministic path from that untrusted text
to a branch on the watcher repo:

1. keep a shallow clone of the watcher repo (``worktree``),
2. cut a fresh branch off the base branch,
3. ``git apply`` each fix (path allowlist, ASCII gate, size caps; one bad
   diff is rejected without sinking the rest),
4. commit, push, and open the PR with ``gh``.

No test run gates the PR: CI owns that, and the verdicts are triaged.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

#: Paths a fix may touch, relative to the watcher repo root.
ALLOWED_PREFIXES = ("src/trustsight/", "tests/")
MAX_FIX_FILES = 10
MAX_ADDED_LINES = 400
MAX_DIFF_CHARS = 32 * 1024

_DASH_LOOKALIKES = frozenset("\u2010\u2011\u2012\u2013\u2014\u2015\u2212")
_REQUIRED_KEYS = ("path", "diff", "summary", "linked_finding")


class FixError(ValueError):
    """A proposed fix is malformed, unsafe, or does not apply."""


def _safe_path(path: str) -> str:
    if not isinstance(path, str) or not path.strip():
        raise FixError("empty path")
    if path.startswith("/") or ".." in Path(path).parts:
        raise FixError("absolute or parent path")
    if not path.startswith(ALLOWED_PREFIXES):
        raise FixError("path outside src/trustsight/ and tests/")
    return path


def _ascii_lines(diff: str) -> None:
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
        bad = next((ch for ch in body
                    if ch in _DASH_LOOKALIKES
                    or (ch != "\t" and not 0x20 <= ord(ch) <= 0x7E)), None)
        if bad is not None:
            raise FixError(f"character not allowed in added line: {bad!r}")
        if " -- " in body:
            raise FixError("double hyphen separator is not allowed")


def validate_fix(entry: dict) -> dict:
    """Validate one code_fixes entry; returns the normalized entry."""

    if not isinstance(entry, dict):
        raise FixError("fix must be an object")
    missing = [k for k in _REQUIRED_KEYS if not isinstance(entry.get(k), str)]
    if missing:
        raise FixError(f"missing string keys: {', '.join(missing)}")
    path = _safe_path(entry["path"])
    diff = entry["diff"]
    if len(diff) > MAX_DIFF_CHARS:
        raise FixError("diff exceeds the size cap")
    if not re.search(r"^\+\+\+ ", diff, re.MULTILINE):
        raise FixError("diff has no +++ header")
    added = sum(1 for line in diff.splitlines()
                if line.startswith("+") and not line.startswith("+++"))
    if added == 0:
        raise FixError("diff adds no lines")
    if added > MAX_ADDED_LINES:
        raise FixError("diff exceeds the added-line cap")
    _ascii_lines(diff)
    return {"path": path, "diff": diff, "summary": entry["summary"],
            "linked_finding": entry["linked_finding"]}


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                          capture_output=True, text=True)


def _git(worktree: Path, *args: str) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=worktree)


def branch_name(package: str, slug: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{slug}-{package}").strip("-")
    return f"triage/{clean or 'fix'}"[:120]


def ensure_worktree(worktree: Path, repo_url: str, base: str, branch: str,
                    log=print) -> None:
    """Shallow clone (first run) and cut *branch* off *base*."""

    if not (worktree / ".git").is_dir():
        worktree.parent.mkdir(parents=True, exist_ok=True)
        if worktree.exists():
            shutil.rmtree(worktree)
        log(f"[pr] cloning {repo_url} -> {worktree}")
        proc = _run(["git", "clone", "--depth", "1", "--branch", base,
                     repo_url, str(worktree)])
        if proc.returncode != 0:
            raise FixError(f"clone failed: {proc.stderr.strip()[:300]}")
    proc = _git(worktree, "fetch", "--depth", "1", "origin", base)
    if proc.returncode != 0:
        raise FixError(f"fetch failed: {proc.stderr.strip()[:300]}")
    proc = _git(worktree, "checkout", "-B", branch, "FETCH_HEAD")
    if proc.returncode != 0:
        raise FixError(f"checkout failed: {proc.stderr.strip()[:300]}")


def apply_fixes(worktree: Path, fixes: list[dict],
                log=print) -> tuple[list[str], list[str]]:
    """Apply validated fixes; returns (applied paths, rejection reasons)."""

    applied: list[str] = []
    rejected: list[str] = []
    for entry in fixes:
        try:
            fix = validate_fix(entry)
        except FixError as exc:
            rejected.append(f"{entry.get('path', '?')}: {exc}")
            log(f"[pr] reject {entry.get('path', '?')}: {exc}")
            continue
        if fix["path"] in applied:
            rejected.append(f"{fix['path']}: duplicate path in one PR")
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False,
                                         dir=str(worktree)) as fh:
            fh.write(fix["diff"] if fix["diff"].endswith("\n")
                     else fix["diff"] + "\n")
            patch = Path(fh.name)
        try:
            check = _git(worktree, "apply", "--check", str(patch))
            if check.returncode != 0:
                rejected.append(f"{fix['path']}: does not apply "
                                f"({check.stderr.strip()[:160]})")
                log(f"[pr] reject {fix['path']}: {check.stderr.strip()[:160]}")
                continue
            _git(worktree, "apply", str(patch))
            applied.append(fix["path"])
            log(f"[pr] applied {fix['path']} ({fix['summary'][:60]})")
        finally:
            patch.unlink(missing_ok=True)
    return applied, rejected


def commit_push_pr(worktree: Path, *, branch: str, repo: str, base: str,
                   title: str, body: str, push: bool = True,
                   log=print) -> dict:
    """Commit the applied fixes, push the branch, open the PR."""

    _git(worktree, "add", "-A")
    commit = _git(worktree, "-c", "user.name=triage-agent",
                  "-c", "user.email=triage-agent@trustsight.org",
                  "commit", "-m", title)
    if commit.returncode != 0 and "nothing to commit" not in commit.stdout:
        raise FixError(f"commit failed: {commit.stderr.strip()[:300]}")
    head = _git(worktree, "rev-parse", "--short", "HEAD").stdout.strip()
    if not push:
        log(f"[pr] dry run: branch {branch} at {head} (not pushed)")
        return {"branch": branch, "commit": head, "pr_url": None}
    proc = _git(worktree, "push", "-u", "origin", branch)
    if proc.returncode != 0:
        raise FixError(f"push failed: {proc.stderr.strip()[:300]}")
    log(f"[pr] pushed {branch} ({head})")
    created = _run(["gh", "pr", "create", "--repo", repo, "--base", base,
                    "--head", branch, "--title", title, "--body", body])
    if created.returncode != 0:
        raise FixError(f"gh pr create failed: "
                       f"{(created.stderr or created.stdout).strip()[:300]}")
    url = created.stdout.strip().splitlines()[-1] if created.stdout.strip() else ""
    log(f"[pr] opened {url}")
    return {"branch": branch, "commit": head, "pr_url": url}


def ship(verdict: dict, *, worktree: Path, repo_url: str, repo: str,
         base: str = "master", push: bool = True, log=print) -> dict:
    """End to end: branch off base, apply the verdict's fixes, open the PR."""

    fixes = verdict.get("code_fixes") or []
    if verdict.get("verdict") != "FP" or not fixes:
        log("[pr] no FP code_fixes; nothing to ship")
        return {"branch": None, "pr_url": None, "applied": [], "rejected": []}
    package = str(verdict.get("package", "package"))
    slug = str(verdict.get("alert_slug", "alert"))
    branch = branch_name(package, slug)
    ensure_worktree(worktree, repo_url, base, branch, log=log)
    applied, rejected = apply_fixes(worktree, fixes[:MAX_FIX_FILES], log=log)
    if not applied:
        log("[pr] every fix was rejected; nothing to commit")
        return {"branch": branch, "pr_url": None, "applied": [],
                "rejected": rejected}
    rules = ", ".join(sorted({f.get("linked_finding", "?") for f in fixes}))
    title = f"fix: clear {rules} false positive on {package}"
    lines = [f"Automated triage fix for {package} ({slug}).", "",
             f"Verdict: FP ({verdict.get('confidence', '?')}).", "",
             str(verdict.get("rationale", ""))[:2000], "", "Fixes:"]
    for fix in fixes:
        if fix.get("path") in applied:
            lines.append(f"- {fix['path']}: {fix.get('summary', '')}")
    if rejected:
        lines += ["", "Rejected by the gate:"] + [f"- {r}" for r in rejected]
    lines += ["", "Opened by the TrustSight triage agent."]
    body = "\n".join(lines)
    result = commit_push_pr(worktree, branch=branch, repo=repo, base=base,
                            title=title, body=body, push=push, log=log)
    result["applied"] = applied
    result["rejected"] = rejected
    return result
