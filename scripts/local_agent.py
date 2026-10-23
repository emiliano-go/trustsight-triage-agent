#!/usr/bin/env python3
"""Triage agent runtime: a local model over the MCP tool servers.

The triage path (the default) is three stages per rule, each its own model
call, so a 9B model is never asked to hold a whole verdict in one turn:

1. SPLIT     two narrow, cited questions: is there a bad practice behind
             this hit, and is there malicious behaviour in the package. The
             runtime maps the answers mechanically to benign_FP /
             malicious_FP / TP; the model never names a class. A TP claim
             must quote the package, and an over-threshold "not malicious"
             needs a grounded rebuttal.
2. SOLVE     the class is an input. The model writes the remedy: owner and
             documentation for a benign FP, the detection-shape change plus
             its true-positive twin for a malicious FP, or the malicious
             evidence and alert path for a TP.
3. ASSEMBLE  report.md, verdict.json and the ledger; --alert renders the
             confirmed-IOC envelope for a TP.

The --prompt-file path keeps the older single-prompt EXPLORE/FIX/VERIFY
flow (below) for the FP-reproducer PR.

Usage (host dev run):

    uv run python scripts/local_agent.py \
        --alert-fixture tests/fixtures/alert_niri_screenshare.json \
        --model ornith-9b-agent:latest --no-push

Env fallbacks: TRIAGE_MODEL_BASE_URL, TRIAGE_MODEL_NAME, TRIAGE_MODEL_API_KEY,
TRIAGE_LOCAL_MAX_TOKENS, TRIAGE_LOCAL_TEMPERATURE.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import difflib
import json
import os
import re
import string
import subprocess
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from triage_agent.fix_pr import ship
from triage_agent.verdicts import extract_verdict


def repo_read(repo_root: Path, arguments: dict) -> str:
    """Read a slice of one file in the watcher checkout.

    The rbg read tool wants an exact chunk id (path:start-end) copied from a
    search result; a small model invents line ranges instead and burns the
    step budget on ValueError. This is the deterministic fallback.
    """

    raw = str(arguments.get("path", "")).strip()
    if not raw or raw.startswith("/") or ".." in Path(raw).parts:
        return "ERROR: path must be repo-relative"
    path = repo_root / raw
    if not path.is_file():
        return f"ERROR: not a file: {raw}"
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return f"ERROR: {exc}"
    start = max(1, int(arguments.get("start_line") or 1))
    end = int(arguments.get("end_line") or 0) or min(len(lines), start + 199)
    end = min(end, len(lines))
    body = "\n".join(f"{i}: {lines[i-1]}" for i in range(start, end + 1))
    return f"{raw}:{start}-{end} ({len(lines)} lines total)\n{body}"


REPO_READ_SPEC = {
    "type": "function",
    "function": {
        "name": "repo_read",
        "description": "Read lines from one file in the watcher repo "
                       "(src/trustsight/ or tests/). Use this instead of "
                       "guessing rbg chunk ids.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
}


def looks_degenerate(text: str) -> bool:
    """True when a turn is a verbatim repetition loop, not an answer."""

    if len(text) < 2000:
        return False
    lines = [ln.strip() for ln in text.splitlines() if len(ln.strip()) > 40]
    if len(lines) < 20:
        return False
    return len(set(lines)) / len(lines) < 0.35


def compact(messages: list[dict], threshold_chars: int,
            keep_recent: int = 8, log=print) -> int:
    """Elide old tool outputs so a long phase keeps fitting the window."""

    def total() -> int:
        return sum(len(m.get("content") or "") for m in messages)

    before = total()
    if before <= threshold_chars:
        return before
    elided = 0
    for m in messages[:-keep_recent]:
        if m.get("role") != "tool":
            continue
        body = m.get("content") or ""
        if len(body) > 400:
            m["content"] = (body[:200] + " ... [elided, "
                            + str(len(body) - 200) + " chars]")
            elided += 1
    log(f"[compact] {before} -> {total()} chars, elided {elided} outputs")
    return total()


def _repair_verify(arguments: dict, alert: dict, log=print) -> dict:
    """Repair the fp_agent_verify argument the way a reviewer would.

    The harness wants {"verdict": {verdict, package, rationale, ...}}. Small
    models pass "kind" instead of "verdict" and forget "package"; both are
    facts the alert already carries, so fill them instead of burning turns
    on a rejected call.
    """

    inner = arguments.get("verdict")
    if not isinstance(inner, dict):
        return arguments
    if "verdict" not in inner and isinstance(inner.get("kind"), str):
        inner["verdict"] = inner.pop("kind")
    if not inner.get("package") and alert.get("package"):
        inner["package"] = alert["package"]
    if not inner.get("rationale"):
        inner["rationale"] = inner.get("finding") or "see evidence"
    if not inner.get("alert_slug") and alert.get("alert_slug"):
        inner["alert_slug"] = alert["alert_slug"]
    log(f"    [adapter] repaired fp_agent_verify -> "
        f"verdict={inner.get('verdict')} package={inner.get('package')}")
    return arguments


def _diff_from_snippet(repo_root: Path, path: str, old: str, new: str) -> str:
    """Build a real unified diff from an old/new snippet pair."""

    target = repo_root / path
    if not target.is_file():
        raise ValueError(f"not a file: {path}")
    text = target.read_text(errors="replace")
    if old not in text:
        raise ValueError(f"old snippet not found verbatim in {path}")
    updated = text.replace(old, new, 1)
    diff = difflib.unified_diff(text.splitlines(), updated.splitlines(),
                                fromfile=f"a/{path}", tofile=f"b/{path}",
                                lineterm="")
    return "\n".join(diff) + "\n"


def fill_missing_new(verdict: dict, repo_root: Path, model: str,
                     base_url: str, api_key: str, timeout: float,
                     max_tokens: int, log=print) -> None:
    """Ask for the replacement lines when the model only gave the old block."""

    for entry in verdict.get("code_fixes") or []:
        if not isinstance(entry, dict):
            continue
        patch = entry.get("patch") if isinstance(entry.get("patch"), dict) else {}
        old = entry.get("old") or patch.get("old") or patch.get("find")
        new = entry.get("new") or patch.get("new") or patch.get("replace")
        path = entry.get("path") or entry.get("file") or patch.get("path")
        if new is not None or not (path and old):
            continue
        prompt = (f"File: {path}\n\nReplace exactly this block:\n\n{old}\n\n"
                  "Return ONLY the replacement lines, as code, with no "
                  "fences, no explanation and no markdown.")
        try:
            data = chat(base_url, api_key, model,
                        [{"role": "user", "content": prompt}], [],
                        temperature=0.2, max_tokens=min(max_tokens, 700),
                        timeout=timeout, reasoning_effort="none",
                        presence_penalty=1.5, frequency_penalty=0.3)
            text = (data["choices"][0]["message"].get("content") or "").strip()
        except Exception as exc:
            log(f"[verdict] replacement call failed: {exc}")
            continue
        if text.startswith("```"):
            text = "\n".join(ln for ln in text.splitlines()
                             if not ln.startswith("```"))
        if text:
            entry["new"] = text + ("\n" if not text.endswith("\n") else "")
            log(f"[verdict] filled replacement for {path} ({len(text)} chars)")


def _fix_entry(entry: dict, rules: list[str], repo_root: Path,
               problems: list[str]) -> dict | None:
    """One code_fixes entry in the shape the PR gate wants, or None."""

    patch = entry.get("patch") if isinstance(entry.get("patch"), dict) else {}
    path = (entry.get("path") or entry.get("file")
            or patch.get("path") or patch.get("file"))
    summary = (entry.get("summary") or entry.get("description")
               or patch.get("summary") or "rule fix")
    linked = (entry.get("linked_finding") or entry.get("rule_id")
              or entry.get("finding_rule_id") or (rules[0] if rules else "?"))
    diff = entry.get("diff") or patch.get("diff")
    if not diff:
        old = entry.get("old") or patch.get("old") or patch.get("find")
        new = entry.get("new") or patch.get("new") or patch.get("replace")
        if path and old and new is not None:
            try:
                diff = _diff_from_snippet(repo_root, path, old, new)
            except ValueError as exc:
                problems.append(f"{path}: {exc}")
                return None
    if not (path and diff):
        problems.append(f"code_fix lacks a path or a usable old/new pair: "
                        f"{sorted(entry)}")
        return None
    recursion = self_recursion_reason(diff)
    if recursion:
        problems.append(f"{path}: {recursion}")
        return None
    return {"path": path, "diff": diff, "summary": str(summary)[:300],
            "linked_finding": str(linked)}


def normalize_verdict(verdict: dict, alert: dict, repo_root: Path,
                      log=print) -> list[str]:
    """Coerce the verdict into the harness/PR shape; return blocking problems."""

    problems: list[str] = []
    verdict.setdefault("schema_version", 1)
    if alert.get("package"):
        verdict.setdefault("package", alert["package"])
    if alert.get("alert_slug"):
        verdict.setdefault("alert_slug", alert["alert_slug"])
    verdict.setdefault("confidence", "medium")
    if not verdict.get("rationale"):
        verdict["rationale"] = verdict.get("summary") or "see evidence"
    rules = alert.get("rules") or []
    if not verdict.get("findings") and verdict.get("verdict") == "FP":
        evidence = verdict.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        verdict["findings"] = [
            {"rule_id": str(rule),
             "reason": str(evidence.get(rule) or verdict["rationale"])[:400],
             "finding": "false trigger",
             "false_trigger": "the rule fired with no bad practice behind it",
             "fix": "see code_fixes"}
            for rule in rules
        ] or [{"rule_id": "unknown", "reason": verdict["rationale"][:400],
               "finding": "false trigger", "false_trigger": "no bad practice",
               "fix": "see code_fixes"}]
    fixed = [f for f in (_fix_entry(e, rules, repo_root, problems)
                         for e in verdict.get("code_fixes") or []
                         if isinstance(e, dict)) if f]
    verdict["code_fixes"] = fixed
    if verdict.get("verdict") == "FP" and not fixed:
        problems.append("an FP verdict needs at least one code_fix")
    log(f"[verdict] normalized: code_fixes={len(fixed)} problems={problems}")
    return problems


#: The harness's PR text allowlist (harness/fp_agent_pr.py). Verdict prose
#: that reaches the PR body must use only these characters.
_PR_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " \t\n\r;:,()-./'_\"|[]+")


def sanitize_text(text) -> str:
    """Drop characters the PR text gate refuses (notably "$", "=", "<")."""

    if not isinstance(text, str):
        text = str(text)
    cleaned = "".join(ch if ch in _PR_ALLOWED else "" for ch in text)
    return cleaned.replace(" -- ", " - ")


def sanitize_verdict_text(verdict: dict, log=print) -> None:
    """Make every prose field PR-safe before the harness formats the PR."""

    changed = 0
    for key in ("rationale", "summary", "version_transition"):
        if isinstance(verdict.get(key), str):
            new = sanitize_text(verdict[key])
            changed += new != verdict[key]
            verdict[key] = new
    evidence = verdict.get("evidence")
    if isinstance(evidence, dict):
        verdict["evidence"] = {k: sanitize_text(v) for k, v in evidence.items()}
    for finding in verdict.get("findings") or []:
        if isinstance(finding, dict):
            for key in ("reason", "finding", "false_trigger", "fix"):
                if isinstance(finding.get(key), str):
                    finding[key] = sanitize_text(finding[key])
    for fix in verdict.get("code_fixes") or []:
        if isinstance(fix, dict) and isinstance(fix.get("summary"), str):
            fix["summary"] = sanitize_text(fix["summary"])
    if changed:
        log(f"[verdict] sanitized {changed} prose field(s) for the PR gate")


def self_recursion_reason(diff: str) -> str | None:
    """Catch a patch that calls the function it is being inserted into.

    Observed from the 9B: it "guards" a predicate by calling the predicate
    again, which is valid syntax, passes the format gate, and only CI finds
    it. Cheap to reject here.
    """

    names: set[str] = set()
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            continue  # added lines are what we are checking
        names.update(re.findall(r"\bdef\s+(\w+)\s*\(", line))
    if not names:
        return None
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for name in names:
            if re.search(rf"\b{re.escape(name)}\s*\(", line[1:]):
                return f"added line calls {name}(), the function it is inside"
    return None


def _bound_names(tree) -> set[str]:
    """Every name a module binds: imports, defs, assignments, targets."""

    import ast
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            names.add(node.name)
            for arg in getattr(node.args, "args", []) if hasattr(node, "args") else []:
                names.add(arg.arg)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_target_names(target))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            names.update(_target_names(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            names.update(_target_names(node.target))
        elif isinstance(node, ast.comprehension):
            names.update(_target_names(node.target))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    names.update(_target_names(item.optional_vars))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def _target_names(node) -> set[str]:
    import ast
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        out: set[str] = set()
        for element in node.elts:
            out |= _target_names(element)
        return out
    return set()


def static_issues(patched_text: str) -> list[str]:
    """Parse the patched file and flag calls to names nothing binds.

    Deterministic, no test suite: catches the 9B's habit of calling a helper
    it just invented, which is valid syntax and only CI would otherwise see.
    """

    import ast
    import builtins
    try:
        tree = ast.parse(patched_text)
    except SyntaxError as exc:
        return [f"syntax error: {exc.msg} (line {exc.lineno})"]
    known = _bound_names(tree) | set(dir(builtins))
    issues: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id not in known:
                issues.append(f"line {node.lineno}: call to unknown "
                              f"{node.func.id}()")
    return sorted(set(issues))[:5]


def fix_is_usable(fix: dict, repo_root: Path) -> bool:
    """True when path is real, old is verbatim in it, and new differs."""

    if not isinstance(fix, dict):
        return False
    path = fix.get("path")
    old = fix.get("old")
    new = fix.get("new")
    if not (isinstance(path, str) and path and isinstance(old, str) and old):
        return False
    if not isinstance(new, str) or new == old:
        return False
    target = repo_root / path
    if not target.is_file():
        return False
    text = target.read_text(errors="replace")
    if old not in text:
        return False
    return not static_issues(text.replace(old, new, 1))


def fix_problems(fix: dict, repo_root: Path) -> list[str]:
    """Why a fix cannot ship yet (empty list means it can)."""

    if not isinstance(fix, dict):
        return ["not an object"]
    path, old, new = fix.get("path"), fix.get("old"), fix.get("new")
    if not (isinstance(path, str) and path and isinstance(old, str) and old):
        return ["needs path and a verbatim old block"]
    if not isinstance(new, str) or not new:
        return ["needs the new block"]
    if new == old:
        return ["new block is identical to old"]
    target = repo_root / path
    if not target.is_file():
        return [f"not a file: {path}"]
    text = target.read_text(errors="replace")
    if old not in text:
        return [f"old block not found verbatim in {path}"]
    patched = text.replace(old, new, 1)
    issues = static_issues(patched)
    diff = "\n".join(difflib.unified_diff(text.splitlines(),
                                          patched.splitlines(),
                                          fromfile=f"a/{path}",
                                          tofile=f"b/{path}", lineterm=""))
    recursion = self_recursion_reason(diff)
    if recursion:
        issues.append(recursion)
    return issues


def repair_fix(fix: dict, summary: str, repo_root: Path, allowed: list[str],
               model: str, base_url: str, api_key: str, timeout: float,
               max_tokens: int, log=print) -> dict | None:
    """Ask again for an exact old/new pair, with the file shown verbatim.

    The model's first answer names a path that may not exist and an "old"
    block that is not in the file. Showing one real file and requiring a
    substring it can copy is a task a 9B can finish.
    """

    path = fix.get("path") if isinstance(fix, dict) else None
    if path not in allowed:
        path = allowed[0] if allowed else None
    if not path:
        return None
    target = repo_root / path
    if not target.is_file():
        return None
    body = _read_lines(target, 240)
    for attempt in range(1, 3):
        prompt = (
            f"File: {path}\n\nExact content:\n{body}\n\n"
            f"Change to make: {summary}\n\n"
            "Return ONE JSON object: {\"path\": \"" + path + "\", "
            "\"old\": \"<lines copied verbatim from the file above>\", "
            "\"new\": \"<the same lines after the change>\"}. "
            "\"old\" must appear character for character in the file. "
            "Keep it to a few lines. No markdown, no commentary.")
        try:
            data = chat(base_url, api_key, model,
                        [{"role": "user", "content": prompt}], [],
                        temperature=0.2, max_tokens=min(max_tokens, 900),
                        timeout=timeout, reasoning_effort="none",
                        presence_penalty=1.5, frequency_penalty=0.3)
            text = (data["choices"][0]["message"].get("content") or "").strip()
        except Exception as exc:
            log(f"[fix] repair call failed: {exc}")
            return None
        doc = _json_doc(text) or {}
        candidate = {"path": doc.get("path") or path,
                     "old": doc.get("old"), "new": doc.get("new"),
                     "summary": summary}
        problems = fix_problems(candidate, repo_root)
        if not problems:
            log(f"[fix] repaired {path} (attempt {attempt})")
            return candidate
        log(f"[fix] repair attempt {attempt}: {problems}")
        summary = (summary + " | previous attempt failed: "
                   + "; ".join(problems))[:600]
    return None


def default_mcp_config(workspace: Path, triage_repo: Path,
                       rbg_repo: Path) -> dict:
    """The wired tool surface, resolved from the workspace layout.

    Paths moved once already (the checkouts now sit under a parent), so the
    layout is a parameter, not a hardcoded JSON file: TRIAGE_WORKSPACE names
    the parent holding trustsight/, trustsight-harness/ and this repo.
    """

    config = {
        "harness": {
            "type": "local", "enabled": True,
            "command": ["uv", "run", "--directory",
                        str(workspace / "trustsight-harness"),
                        "--extra", "mcp", "harness-mcp"],
        },
        "aur": {
            "type": "local", "enabled": True,
            "command": [str(triage_repo / ".venv" / "bin" / "python"),
                        "-m", "triage_agent.aur_mcp"],
        },
    }
    # rbg is only used by the legacy FP-reproducer path; the triage route
    # needs harness + aur alone, so a deployment without that checkout
    # still starts.
    if (rbg_repo / "mcp_main.py").is_file():
        config["rbg"] = {
            "type": "local", "enabled": True,
            "command": ["/usr/bin/python3", str(rbg_repo / "mcp_main.py")],
            "environment": {"HARNESS_ALLOWED_ROOTS": "/"},
            "arg_defaults": {"root": str(workspace / "trustsight")},
        }
    return config


class Snapshot:
    """Package facts fetched once and reused across rules."""

    def __init__(self, hub: McpHub, alert: dict, log=print):
        self.hub = hub
        self.alert = alert
        self.log = log
        self.cache: dict[str, str] = {}

    async def _call(self, tool: str, args: dict) -> str:
        key = tool + json.dumps(args, sort_keys=True)
        if key not in self.cache:
            try:
                self.cache[key] = await self.hub.call(tool, args)
            except Exception as exc:
                self.cache[key] = f"ERROR: {exc}"
        return self.cache[key]

    def fixture_tree(self) -> dict | None:
        """A test fixture may carry its own package tree instead of the AUR."""

        tree = self.alert.get("tree")
        if not tree:
            return None
        return {"PKGBUILD": tree} if isinstance(tree, str) else dict(tree)

    async def pkgbuild(self) -> str:
        tree = self.fixture_tree()
        if tree is not None:
            return tree.get("PKGBUILD") or "(fixture tree has no PKGBUILD)"
        return await self._call("harness_aur_pkgbuild",
                                {"package": self.alert.get("package", "")})

    async def aur_info(self) -> str:
        if "aur_info" in self.alert:
            return str(self.alert["aur_info"])
        if self.fixture_tree() is not None:
            return "(fixture package: no live AUR metadata)"
        return await self._call("harness_aur_info",
                                {"packages": [self.alert.get("package", "")]})

    async def triage(self) -> str:
        if "triage" in self.alert:
            triage = self.alert["triage"]
            return (triage if isinstance(triage, str)
                    else json.dumps(triage, indent=1))
        slug = self.alert.get("alert_slug")
        if not slug:
            return "(no slug)"
        return await self._call("harness_fp_triage", {"alert_slug": slug})

    async def git_log(self) -> str:
        if "git_log" in self.alert:
            return str(self.alert["git_log"])
        if self.fixture_tree() is not None:
            return "(fixture package: no live git history)"
        return await self._call("aur_git_log",
                                {"package": self.alert.get("package", ""),
                                 "limit": 5})

    async def grounded_evidence(self, finding: dict | None) -> str:
        """The citable package facts: tree, diff, extra files, alert evidence.

        Rule cards and rule source are deliberately excluded: a claim about
        the package has to point at the package, not at the rule's docs.
        """

        pkgbuild = await self.pkgbuild()
        diff = str(self.alert.get("diff") or "")
        return "\n".join([
            pkgbuild,
            diff,
            *decoded_payloads(pkgbuild + "\n" + diff),
            await self.extra_files(),
            await self.triage(),
            json.dumps(finding or {}),
        ])

    async def package_evidence(self) -> str:
        """Just the package: tree, diff, decoded payloads, extra files.

        The rule card, rule source, finding metadata and feed triage are
        excluded: they describe the suspicion, not the package, and a
        keyword in the card must never satisfy an effect check.
        """

        pkgbuild = await self.pkgbuild()
        diff = str(self.alert.get("diff") or "")
        return "\n".join([
            pkgbuild,
            diff,
            *decoded_payloads(pkgbuild + "\n" + diff),
            await self.extra_files(),
        ])

    async def extra_files(self) -> str:
        """Every non-PKGBUILD file of the snapshot (.install, patches)."""

        tree = self.fixture_tree()
        if tree is not None:
            files = {k: v for k, v in tree.items()
                     if k not in ("PKGBUILD", ".SRCINFO")}
            return "\n\n".join(f"### file {k}\n{v}"
                                for k, v in list(files.items())[:4]) \
                or "(no extra snapshot files)"
        raw = await self.pkgbuild()
        doc = _json_doc(raw)
        files = [f for f in (doc or {}).get("files", [])
                 if f not in ("PKGBUILD", ".SRCINFO")]
        out = []
        for name in files[:4]:
            out.append(f"### file {name}\n"
                       + await self._call("aur_file",
                                          {"package": self.alert.get("package", ""),
                                           "filename": name}))
        return "\n\n".join(out) or "(no extra snapshot files)"


def _read_lines(path: Path, limit: int = 200) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return f"ERROR: {exc}"
    body = "\n".join(f"{i}: {lines[i-1]}" for i in range(1, min(limit, len(lines)) + 1))
    more = "" if len(lines) <= limit else f"\n... ({len(lines) - limit} more lines)"
    return body + more


def rule_files(repo_root: Path, rule: str, limit: int = 2) -> list[Path]:
    """Files that literally name the rule id, rule source first."""

    hits = subprocess.run(
        ["grep", "-rl", "--include=*.py", f'"{rule}"', str(repo_root / "src")],
        capture_output=True, text=True).stdout.split()
    files = [Path(h) for h in hits]
    files.sort(key=lambda p: ("analysis" not in str(p), str(p)))
    return files[:limit]


def rule_card(repo_root: Path, rule: str) -> str:
    """The rule's authored card: intent and known noise, by file name.

    Cards live in docs_src/sections/<anchor>.md; code rules use their id as
    the anchor (r054.md), scorer modifiers have no card of their own and the
    rule source is the fallback.
    """

    sections = repo_root / "docs_src" / "sections"
    direct = sections / f"{rule.lower()}.md"
    if direct.is_file():
        return _read_lines(direct, 60)
    for path in sorted(sections.glob("*.md")):
        text = path.read_text(errors="replace")
        if f"anchor: {rule.lower()}" in text:
            return _read_lines(path, 60)
    return "(no card for this rule; the rule source is the authority)"


def rule_docs(repo_root: Path, rule: str) -> str:
    """The rule's own documentation section, if the repo has one."""

    hits = subprocess.run(
        ["grep", "-rl", rule, str(repo_root / "docs_src"),
         str(repo_root / "docs")], capture_output=True, text=True).stdout.split()
    out = []
    for h in hits[:2]:
        out.append(f"### doc {Path(h).name}\n" + _read_lines(Path(h), 80))
    return "\n\n".join(out) or "(no rule doc found)"


async def rule_bundle(snapshot: Snapshot, repo_root: Path, alert: dict,
                      rule: str, finding: dict | None, log=print) -> str:
    """Everything the model needs to judge ONE rule, fetched by the runtime."""

    parts = [
        f"### package\n{alert.get('package')} "
        f"({alert.get('old_version')} to {alert.get('new_version')})",
        "### PKGBUILD\n" + (await snapshot.pkgbuild()),
        *(["### diff under triage\n" + str(alert["diff"])]
          if alert.get("diff") else []),
        *(["### decoded payloads (runtime-decoded; trust these)\n"
           + "\n".join(f"- {d}" for d in decoded_payloads(
               (await snapshot.pkgbuild()) + "\n"
               + str(alert.get("diff") or "")))]),
        "### aur metadata\n" + (await snapshot.aur_info()),
        "### alert triage evidence\n" + (await snapshot.triage()),
        "### recent AUR commits\n" + (await snapshot.git_log()),
        "### other snapshot files\n" + (await snapshot.extra_files()),
        f"### finding for {rule} (pipeline metadata)\n"
        + json.dumps(finding or {}, indent=1),
        f"### rule card for {rule}\n" + rule_card(repo_root, rule),
    ]
    for path in rule_files(repo_root, rule):
        parts.append(f"### rule source {path.relative_to(repo_root)}\n"
                     + _read_lines(path, 200))
    parts.append("### rule documentation\n" + rule_docs(repo_root, rule))
    bundle = "\n\n".join(parts)
    log(f"[bundle] {rule}: {len(bundle)} chars")
    return bundle


class McpTool:
    def __init__(self, server: str, name: str, raw_name: str,
                 description: str, schema: dict):
        self.server = server
        self.name = name          # name the model sees
        self.raw_name = raw_name  # name the MCP server answers to
        self.description = description or ""
        self.schema = schema or {"type": "object", "properties": {}}

    def openai_spec(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description[:1024],
                "parameters": self.schema,
            },
        }


class McpHub:
    """Start every MCP server once and route tool calls to the right session."""

    def __init__(self, config: dict, log=print, alert: dict | None = None):
        self.config = config
        self.log = log
        self.stack = AsyncExitStack()
        self.sessions: dict[str, ClientSession] = {}
        self.tools: dict[str, McpTool] = {}
        self.defaults: dict[str, dict] = {}
        self.alert = alert or {}

    async def start(self) -> None:
        for server, spec in self.config.items():
            if spec.get("type", "local") != "local" or not spec.get("enabled", True):
                continue
            cmd = list(spec["command"])
            env = {**os.environ, **(spec.get("environment") or {})}
            self.defaults[server] = dict(spec.get("arg_defaults") or {})
            params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)
            try:
                read, write = await self.stack.enter_async_context(
                    stdio_client(params))
                session = await self.stack.enter_async_context(
                    ClientSession(read, write))
                await session.initialize()
                listed = await session.list_tools()
            except Exception as exc:  # a dead server must not kill the run
                self.log(f"[mcp] {server}: failed to start: {exc}")
                continue
            self.sessions[server] = session
            for tool in listed.tools:
                exposed = (tool.name if tool.name.startswith(server + "_")
                           else f"{server}_{tool.name}")
                self.tools[exposed] = McpTool(
                    server, exposed, tool.name, tool.description,
                    tool.input_schema)
            self.log(f"[mcp] {server}: {len(listed.tools)} tools")
        self.log(f"[mcp] total tools: {len(self.tools)}")

    async def close(self) -> None:
        await self.stack.aclose()

    async def call(self, name: str, arguments: dict) -> str:
        tool = self.tools.get(name)
        if tool is None:
            matches = [t for key, t in self.tools.items()
                       if key == name or key.endswith("_" + name)]
            if len(matches) == 1:
                tool = matches[0]
                name = tool.name
                self.log(f"    [adapter] resolved tool name -> {name}")
            else:
                return f"ERROR: unknown tool {name}"
        session = self.sessions[tool.server]
        raw = tool.raw_name
        for key, value in self.defaults.get(tool.server, {}).items():
            given = arguments.get(key)
            if given is None or (key == "root" and not str(given).startswith("/")):
                arguments[key] = value
        if raw == "fp_agent_verify":
            arguments = _repair_verify(arguments, self.alert, self.log)
        try:
            result = await session.call_tool(raw, arguments)
        except Exception as exc:
            return f"ERROR: {exc}"
        parts = []
        for item in result.content or []:
            text = getattr(item, "text", None)
            parts.append(text if text is not None else str(item))
        body = "\n".join(parts).strip() or "(empty result)"
        if getattr(result, "isError", False):
            body = "ERROR: " + body
        return body


def chat(base_url: str, api_key: str, model: str, messages: list, tools: list,
         *, temperature: float, max_tokens: int, timeout: float,
         reasoning_effort: str = "", presence_penalty: float = 0.0,
         frequency_penalty: float = 0.0) -> dict:
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    # A thinking model can spend the whole budget on reasoning and return
    # neither content nor a tool call. "none" turns that off.
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort
    # A 9B with no penalty repeats a paragraph until the token cap.
    if presence_penalty:
        payload["presence_penalty"] = presence_penalty
    if frequency_penalty:
        payload["frequency_penalty"] = frequency_penalty
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    url = base_url.rstrip("/") + "/chat/completions"
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


class Phase:
    """One bounded conversation: tools, steps, compaction, guards."""

    def __init__(self, name: str, *, hub: McpHub, repo_root: Path,
                 model: str, base_url: str, api_key: str, timeout: float,
                 temperature: float, max_tokens: int, context: int,
                 reasoning_effort: str, tools: list[dict], log=print,
                 text_from: int = 1):
        self.name = name
        self.hub = hub
        self.repo_root = repo_root
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.threshold = int(context * 0.4 * 4)
        self.reasoning_effort = reasoning_effort
        self.tools = tools
        self.text_from = text_from  # no tools in the last N steps
        self.log = log
        self.calls: dict[tuple, int] = {}

    async def run(self, messages: list[dict], *, max_steps: int) -> str:
        self.log(f"\n=== {self.name}: up to {max_steps} steps ===")
        nudges = 0
        bad_turns = 0
        force_text = False
        final = ""
        for step in range(1, max_steps + 1):
            compact(messages, self.threshold, log=self.log)
            left = max_steps - step
            if left <= self.text_from - 1:
                force_text = True  # no tools left: the model must answer
            if left <= 2 and not force_text:
                messages.append({"role": "user", "content":
                                 f"{left} steps left. Stop exploring and "
                                 "answer with the required JSON now."})
            started = time.time()
            data = chat(self.base_url, self.api_key, self.model, messages,
                        [] if force_text else self.tools,
                        temperature=self.temperature, max_tokens=self.max_tokens,
                        timeout=self.timeout,
                        reasoning_effort=self.reasoning_effort,
                        presence_penalty=1.5, frequency_penalty=0.3)
            choice = data["choices"][0]
            msg = choice["message"]
            calls = msg.get("tool_calls") or []
            content = msg.get("content") or ""
            self.log(f"[{self.name} {step}/{max_steps}] "
                     f"{time.time()-started:.1f}s content={len(content)}c "
                     f"tools={len(calls)} finish={choice.get('finish_reason')}")
            messages.append({
                "role": "assistant", "content": content,
                **({"tool_calls": calls} if calls else {}),
            })
            errors = 0
            for call in calls:
                fn = call["function"]["name"]
                raw_args = call["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw_args)
                except ValueError:
                    args = {}
                signature = (fn, json.dumps(args, sort_keys=True))
                self.calls[signature] = self.calls.get(signature, 0) + 1
                if self.calls[signature] > 3:
                    result = ("ERROR: this exact call was already made; the "
                              "result is in context. Move on.")
                    self.log(f"    -> {fn} [repeat blocked]")
                else:
                    self.log(f"    -> {fn}({json.dumps(args)[:110]})")
                    result = (repo_read(self.repo_root, args)
                              if fn == "repo_read"
                              else await self.hub.call(fn, args))
                    self.log(f"       {result[:160].replace(chr(10), ' ')}")
                if result.startswith("ERROR") or "error" in result[:40]:
                    errors += 1
                messages.append({"role": "tool",
                                 "tool_call_id": call.get("id") or fn,
                                 "content": result[:6000]})
            if calls and errors == len(calls):
                bad_turns += 1
                if bad_turns >= 3:
                    force_text = True
                    self.log(f"[{self.name}] tools failing; forcing text")
                    messages.append({"role": "user", "content":
                                     "Stop calling tools and answer now."})
            else:
                bad_turns = 0
            if calls:
                continue
            text = content.strip()
            if looks_degenerate(text) and nudges < 3:
                nudges += 1
                self.log(f"[{self.name}] degenerate output; nudge {nudges}/3")
                messages.append({"role": "user", "content":
                                 "That output repeated itself. Answer now."})
                continue
            if not text and nudges < 2:
                nudges += 1
                self.log(f"[{self.name}] empty turn; nudge {nudges}/2")
                messages.append({"role": "user", "content":
                                 "Answer now."})
                continue
            final = text
            break
        else:
            self.log(f"[{self.name}] hit the step cap")
        return final


def _json_doc(text: str) -> dict | None:
    """Any JSON object in the text, preferring one that looks like a verdict."""

    import re
    best = None
    for match in re.finditer(r"\{", text):
        try:
            doc, _ = json.JSONDecoder().raw_decode(text[match.start():])
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        if "verdict" in doc and "package" in doc:
            return doc
        best = best or doc
    return best


def verdict_doc(text: str) -> dict | None:
    """The verdict document, however loosely the model wrapped it.

    A 9B often emits the verdict inside a pseudo tool-call wrapper, with
    escaped newlines, and without schema_version. Accept all three.
    """

    strict = extract_verdict(text)
    if strict is not None:
        return strict
    candidates = [text]
    stripped = text.strip()
    if stripped.startswith('"') and stripped.endswith('"'):
        candidates.append(stripped[1:-1])
    for candidate in candidates:
        for chunk in (candidate, candidate.replace("\\n", "\n")):
            doc = _json_doc(chunk)
            if doc and "verdict" in doc and "package" in doc:
                doc.setdefault("schema_version", 1)
                return doc
    return None


RULE_QUESTION = """

--- ONE RULE, ONE ANSWER ---
Judge ONLY the rule above. You have all the evidence; do not ask for more.
Use the TrustSight vocabulary: a benign false positive is a real bad practice
by the packager (the rule works), a malicious false positive is a bad trigger
with no bad practice behind it (fix the detection shape and keep its
true-positive twin), and a true positive is real malicious behaviour.

Your FINAL message is exactly one JSON object:
{"rule_id": "%(rule)s",
 "class": "benign_false_positive|malicious_false_positive|true_positive",
 "root_cause": "<what the rule code does, or why the finding is real>",
 "evidence": "<what the evidence shows>",
 "fix": {"path": "src/trustsight/... or tests/...",
         "summary": "<one line>",
         "old": "<the exact lines to replace, copied character for character>",
         "new": "<the replacement lines>"}}
Include "fix" for both false-positive classes (a malicious one changes the
detection shape, a benign one documents the known false positive and adds its
test). Omit "fix" only for a true positive. No markdown, no commentary.
"""

PHASE1 = """

--- PHASE 1: DIAGNOSE (no diffs yet) ---
Investigate the alert with the tools. For every rule that fired, decide its
class, find the code that produced it and the root cause. Do not write any
diff yet. When you are done, your FINAL message is exactly one JSON object:
{"package": "<name>", "verdict": "FP|TP|uncertain",
 "confidence": "high|medium|low", "summary": "<one paragraph>",
 "rules": [{"rule_id": "<id>", "class": "benign_false_positive
 |malicious_false_positive|true_positive", "code_path": "<src/...>",
 "root_cause": "<what the code does wrong, or why the finding is real>",
 "evidence": "<what you checked>", "fix_plan": "<the detection-shape change
 and its true-positive twin, or 'document as known FP'>"}]}
"""

PHASE2 = """

--- PHASE 2: WRITE THE VERDICT ---
You have already investigated; the diagnosis is below. Do NOT re-explore.
Your only job now is the verdict document. Call repo_read only when you need
exact source lines to make a diff apply. Then output ONE JSON object and
nothing else: the verdict schema with "evidence" for every fired rule and
"code_fixes" (at least one) for an FP verdict. An FP verdict without
code_fixes is invalid, and "findings" must be a non-empty list with one
entry per fired rule.

Each code_fixes entry is exactly:
{"path": "src/trustsight/....py", "linked_finding": "<rule id>",
 "summary": "<one line>", "old": "<the exact lines to replace, copied
 character for character from the file>", "new": "<the replacement lines>"}
The runtime turns old/new into the diff, so do not write a diff yourself.
"old" must appear verbatim in the file or the fix is rejected. Write the
JSON now.
"""


async def run(args, alert: dict | None, mcp_config: dict,
              rules: list[str], findings: list[dict], log=print) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    hub = McpHub(mcp_config, log=log, alert=alert)
    await hub.start()
    if not hub.tools:
        log("[agent] no MCP tools started")
        await hub.close()
        return 1
    verdict: dict | None = None
    try:
        snapshot = Snapshot(hub, alert or {}, log=log)
        per_rule: list[dict] = []
        for rule in rules:
            finding = next((f for f in findings
                            if str(f.get("rule", f.get("rule_id", ""))) == rule),
                           None)
            bundle = await rule_bundle(snapshot, Path(args.repo_root),
                                       alert or {}, rule, finding, log=log)
            (out_dir / f"bundle-{rule}.txt").write_text(bundle)
            head = (f"Alert for AUR package {alert.get('package')} "
                    f"({alert.get('old_version')} to "
                    f"{alert.get('new_version')}).\n\n"
                    "--- EVIDENCE (gathered by the runtime) ---\n"
                    f"{bundle}\n")
            question = head + RULE_QUESTION.replace("%(rule)s", rule)
            answer = ""
            for _attempt in range(1, 3):
                phase = Phase(
                    f"rule-{rule}", hub=hub, repo_root=Path(args.repo_root),
                    model=args.model, base_url=args.base_url,
                    api_key=args.api_key, timeout=args.timeout,
                    temperature=args.temperature, max_tokens=args.max_tokens,
                    context=args.context,
                    reasoning_effort=args.reasoning_effort, tools=[],
                    text_from=1, log=log)
                answer = await phase.run([{"role": "user", "content": question}],
                                         max_steps=2)
                doc = _json_doc(answer)
                if doc and (doc.get("class") or doc.get("fix")):
                    break
                question += ("\n\nThat answer was not the required JSON. "
                             "Return the one JSON object now.")
            (out_dir / f"answer-{rule}.txt").write_text(answer)
            doc = _json_doc(answer) or {"rule_id": rule, "class": "uncertain"}
            doc["rule_id"] = doc.get("rule_id") or rule
            fix = doc.get("fix")
            if isinstance(fix, dict) and fix:
                allowed = [str(f.relative_to(Path(args.repo_root)))
                           for f in rule_files(Path(args.repo_root), rule, 3)]
                problems = fix_problems(fix, Path(args.repo_root))
                if problems and allowed:
                    repaired = repair_fix(
                        fix, str(fix.get("summary") or doc.get("root_cause")
                                 or "fix the false trigger"),
                        Path(args.repo_root), allowed, args.model,
                        args.base_url, args.api_key, args.timeout,
                        args.max_tokens, log=log)
                    if repaired:
                        fix = repaired
                problems = fix_problems(fix, Path(args.repo_root))
                if not problems:
                    fix.setdefault("linked_finding", rule)
                    doc["code_fixes"] = [fix]
                    log(f"[rule {rule}] fix usable on {fix.get('path')}")
                else:
                    log(f"[rule {rule}] fix rejected: {problems}")
            per_rule.append(doc)
            log(f"[rule {rule}] class={doc.get('class')} "
                f"fix={'yes' if fix else 'no'}")

        classes = {r.get("class") for r in per_rule}
        if "true_positive" in classes:
            overall = "TP"
        elif classes and classes <= {"benign_false_positive",
                                     "malicious_false_positive"}:
            overall = "FP"
        else:
            overall = "uncertain"
        fixes: list[dict] = []
        for r in per_rule:
            fixes.extend(r.get("code_fixes") or [])
        verdict = {
            "schema_version": 1,
            "package": (alert or {}).get("package"),
            "alert_slug": (alert or {}).get("alert_slug"),
            "verdict": overall,
            "confidence": "medium",
            "rationale": " | ".join(
                f"{r['rule_id']}: {r.get('class')} - "
                f"{str(r.get('root_cause', ''))[:200]}" for r in per_rule),
            "evidence": {r["rule_id"]: str(r.get("evidence", ""))[:600]
                         for r in per_rule},
            "findings": [{"rule_id": r["rule_id"],
                          "reason": str(r.get("evidence", ""))[:400],
                          "finding": str(r.get("class", ""))[:60],
                          "false_trigger": str(r.get("root_cause", ""))[:200],
                          "fix": "see code_fixes"} for r in per_rule],
            "code_fixes": fixes,
        }
        (out_dir / "verdict-raw.json").write_text(
            json.dumps(verdict, indent=2, sort_keys=True))
        problems = normalize_verdict(verdict, alert or {},
                                     Path(args.repo_root), log=log)
        sanitize_verdict_text(verdict, log=log)
        (out_dir / "verdict.json").write_text(
            json.dumps(verdict, indent=2, sort_keys=True))
        log(f"[agent] verdict={verdict['verdict']} "
            f"code_fixes={len(verdict.get('code_fixes') or [])} "
            f"problems={problems}")
        if not problems:
            result = await hub.call("harness_fp_agent_verify",
                                    {"verdict": verdict})
            (out_dir / "verify.txt").write_text(result)
            log(f"[verify] fp_agent_verify -> {result[:300]}")
    finally:
        await hub.close()

    if verdict is None:
        log("[agent] no verdict produced")
        return 1
    if args.no_ship:
        return 0
    ship_args = {"worktree": Path(args.worktree), "repo_url": args.repo_url,
                 "repo": args.repo, "base": args.base,
                 "push": not args.no_push}
    try:
        shipped = ship(verdict, log=log, **ship_args)
    except Exception as exc:
        log(f"[pr] shipping failed: {exc}")
        return 1
    (out_dir / "pr.json").write_text(json.dumps(shipped, indent=2))
    if shipped.get("pr_url"):
        log(f"[pr] PR: {shipped['pr_url']}")
    return 0


BAD_PRACTICE_QUESTION = """

--- STAGE 1 of 3: IS A BAD PRACTICE BEHIND THIS HIT? ---
The rule card above states what the rule exists to surface and what it knows
about its own noise. Read the card, the rule source and the evidence, then
answer ONE question:

Does the PACKAGER do something genuinely undesirable here, something the
rule is right to surface? This is not the question "is the package
malicious": a normal packaging idiom that the rule happens to match is NOT a
bad practice.

Cite the exact line you rely on: a PKGBUILD line, a sentence from the rule
card, or a line of the rule source. An answer without a citation is not
usable.

Your FINAL message is exactly one JSON object and nothing else. No prose,
no preamble, no explanation outside the JSON:
{"rule_id": "%(rule)s",
 "bad_practice_present": true|false,
 "citation": "<the exact line you rely on>",
 "reasoning": "<one or two sentences>",
 "confidence": "high|medium|low"}
"""

MALICIOUS_QUESTION = """

--- STAGE 2 of 3: IS THERE MALICIOUS BEHAVIOUR IN THIS PACKAGE? ---
Ignore what the rule intended to detect. From the evidence, is there actual
malicious behaviour in this package: an IOC, impersonation, exfiltration, a
hidden payload, or a build that runs something it should not? A package that
is merely unconventional is not malicious.

Never decode encoded text yourself: if the runtime provides a decoded
payload, use that value; if the text cannot be decoded from the evidence, do
not guess a plaintext. For a "no" answer, cite the fact that makes the
behaviour benign (an official host, a static unit file, a plain download),
not merely the suspicious line. An answer without a citation is not usable.

Your FINAL message is exactly one JSON object and nothing else. No prose,
no preamble, no explanation outside the JSON:
{"rule_id": "%(rule)s",
 "malicious_behaviour_present": true|false,
 "citation": "<the exact line you rely on>",
 "reasoning": "<one or two sentences>",
 "confidence": "high|medium|low"}
"""

SOLVE_QUESTION = """

--- STAGE 3 of 3: RESOLVE THIS FINDING ---
The runtime has already fixed the classification from the two answers above:
%(klass)s. Do not re-classify. Write the resolution for that class only.

- benign_false_positive: the bad practice is real. Say who owns it (the
  packager) and what they should change, or where to document the hit as a
  known false positive.
- malicious_false_positive: the rule fired with no bad practice behind it.
  Describe the detection-shape change that stops this trigger AND keeps the
  true-positive case the rule exists for (its true-positive twin). Name the
  code path from the rule source above.
- true_positive: summarise the malicious evidence and the alert path, and
  list the IOCs tied to the malicious behaviour itself (the payload host,
  the exfiltration endpoint, a payload hash) as ioc_entries. Do NOT list the
  package's legitimate source URLs, its AUR page, or upstream mirrors; those
  are not IOCs. An empty list is correct when there is none.

Your FINAL message is exactly one JSON object:
{"rule_id": "%(rule)s", "class": "%(klass)s",
 "resolution": "<the remedy for that class>",
 "where": "<file or function the change or documentation belongs to>",
 "tp_twin": "<for a malicious FP: the malicious case that must keep firing>",
 "evidence": "<the citable fact that justifies the remedy>",
 "ioc_entries": [{"type": "domain|url|hash|ip", "value": "...",
                  "confidence": "high|medium|low",
                  "provenance": "<where in the package you saw it>"}]}
"""


def _normalise(text: str) -> str:
    return " ".join(str(text).split())


_B64_ECHO = re.compile(
    r"echo\s+(['\"]?)([A-Za-z0-9+/=]{12,})\1\s*\|\s*base64\s+(?:-d|--decode)\b")


def decoded_payloads(text: str) -> list[str]:
    """Decode `echo <b64> | base64 -d` payloads so the model never guesses.

    A 9B model asked to eyeball base64 invents plausible plaintext; the
    runtime decodes it deterministically instead.
    """

    out: list[str] = []
    for match in _B64_ECHO.finditer(text):
        try:
            decoded = base64.b64decode(match.group(2), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and decoded.strip():
            out.append(decoded)
    return out


_QUOTED = re.compile(r"[\"'`]([^\"'`]{8,})[\"'`]")


def grounded_in(citation, evidence: str) -> bool:
    """Does the citation quote a line the runtime actually put in evidence?

    Models often wrap the quote and append commentary ("... - reason field
    of finding 2"). Test the whole text, then the quoted spans, then the
    longest line, so a real quote is not lost to the model's own gloss.
    """

    if not citation:
        return False
    haystack = _normalise(evidence)
    raw = [_normalise(citation).strip("`'\" ")]
    raw += [_normalise(m) for m in _QUOTED.findall(str(citation))]
    raw += [_normalise(line).strip("`'\" ")
            for line in str(citation).splitlines()]
    candidates = set()
    for cand in raw:
        candidates.add(cand)
        # Models append their own gloss: "curl ... | bash (PKGBUILD, line 12)".
        for match in re.finditer(r"\s+[(\[]", cand):
            prefix = cand[:match.start()].strip()
            if prefix:
                candidates.add(prefix)
        for sep in (" - ", " \u2014 ", ": "):
            if sep in cand:
                candidates.add(cand.split(sep, 1)[0].strip())
    return any(len(c) >= 8 and c in haystack for c in candidates)


_ALERT_ALLOWED = frozenset(string.ascii_letters + string.digits
                            + " \t\n\r;:,()-./'_\"|[]+")
_ALERT_DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"


def alert_text(text) -> str:
    """Coerce free text into the harness alert envelope's ASCII allowlist."""

    text = str(text).translate({ord(c): "-" for c in _ALERT_DASHES})
    text = text.replace(" -- ", " - ")
    text = "".join(c if c in _ALERT_ALLOWED else " " for c in text)
    return " ".join(text.split())


def citation_ok(bad_cite, evil_v, evil_cite, evil_grounded: bool,
                need_grounding: bool) -> bool:
    """A TP rests on the malicious answer alone; an FP needs both answers.

    A missing Q1 answer must not turn a grounded Q2 "yes" into uncertainty:
    the class mapping already ignores Q1 when Q2 is yes.
    """

    if evil_v is True:
        return bool(evil_cite) and evil_grounded
    return (bool(bad_cite) and bool(evil_cite)
            and (evil_grounded or not need_grounding))


_SHELLS = (r"(?:/(?:usr/)?bin/)?(?:ba|z|da|k|mk|pd|ya|po|a)?sh\b"
           r"|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua")
_MALICIOUS_EFFECT = tuple(re.compile(p) for p in (
    # Fetch or decode piped into an interpreter (R001/R003 shapes).
    r"\|\s*(?:sudo\s+|doas\s+|env\s+)?(?:" + _SHELLS + r")\b",
    r"\bbase64\s+(?:-d|--decode)\b[^\n]*\|",
    # Interpreter-direct invocation of a string.
    r"\beval\b", r"\bsh\s+-c\b",
    r"\bsource\s+/dev/stdin\b|\.\s+/dev/stdin\b",
    # Network exfiltration or a reverse shell.
    r"/dev/tcp/", r"\b(?:nc|ncat|netcat)\s+[^\n]*\s\d{2,5}\b",
    r"\bcurl\b[^\n]*(?:\s-d\s*@|--data(?:-binary)?\s+@|\s-F\s+\S+=@)",
    r"\bwget\b[^\n]*--post-(?:data|file)",
    # Writes or persistence outside the build directories.
    r"(?:>|>>)\s*/(?:etc|root|home|usr/local|var/spool/cron)/",
    r"\b(?:useradd|adduser|chpasswd)\b", r"authorized_keys", r"\bcrontab\b",
    r"\brm\s+-[a-z]*[rf][a-z]*\s+/(?:\s|$|\*)",
    # Download-then-run and local-script execution shapes.
    r"(?:^|[;&|]\s*|\n\s*)(?:sudo\s+|doas\s+)?(?:ba|z|da|k)?sh\s+\S+",
    r"(?:^|[;&|]\s*|\n\s*)\./[^\s]+",
    r"(?:^|[;&|]\s*|\n\s*)(?:python3?|perl|ruby|node|php|lua)\s+"
    r"\S+\.(?:py|pl|rb|js|php|lua)\b",
))


def has_malicious_effect(text: str) -> bool:
    """Is there a concrete mechanism for harm anywhere in the package?

    This gates a *yes* answer only: a model may not call a package
    malicious when its evidence contains no execution, exfiltration or
    persistence construct at all. A fetch to a file, a normal build
    command, and even a suspicious URL are not enough on their own.
    """

    return any(pattern.search(text) for pattern in _MALICIOUS_EFFECT)


def class_from_facts(bad_practice: bool | None,
                     malicious: bool | None) -> str:
    """The Standards mapping, applied mechanically to the two facts.

    An unanswered question is not a "no": it leaves the class undecided
    rather than quietly labelling the hit a bad rule trigger.
    """

    if malicious is True:
        return "true_positive"
    if bad_practice is True:
        return "benign_false_positive"
    if bad_practice is False:
        return "malicious_false_positive"
    return "uncertain"


_CLASSES = ("benign_false_positive", "malicious_false_positive", "true_positive")


async def ask_json(phase: Phase, question: str, rule: str,
                   keys: tuple[str, ...], log=print) -> dict:
    """One JSON answer, with one retry when the expected fields are absent."""

    for attempt in (1, 2):
        text = await phase.run([{"role": "user", "content": question}],
                               max_steps=2)
        doc = _json_doc(text) or {}
        if any(k in doc for k in keys):
            return doc
        log(f"[{rule}] answer {attempt} lacked {keys}; asking again")
        question += ("\n\nThat was not the required JSON object. Return it "
                     "now, nothing else.")
    return {}


async def triage_package(hub: McpHub, snapshot: Snapshot, alert: dict,
                         rules: list[str], findings: list[dict], args,
                         out_dir: Path, log=print) -> dict:
    """Three stages per rule: bad practice, malicious behaviour, resolution.

    The model is never asked to name a class. It answers two narrow, cited
    questions; the runtime maps them to the Standards vocabulary. The solve
    stage receives the class as an input and cannot change it.
    """

    phase = Phase("triage", hub=hub, repo_root=Path(args.repo_root),
                  model=args.model, base_url=args.base_url,
                  api_key=args.api_key, timeout=args.timeout,
                  temperature=args.temperature,
                  max_tokens=min(args.max_tokens, 3000),
                  context=args.context,
                  reasoning_effort=args.reasoning_effort, tools=[],
                  text_from=1, log=log)
    score = alert.get("score")
    threshold = getattr(args, "score_threshold", 20)
    high_score = isinstance(score, (int, float)) and score >= threshold
    effect_text = await snapshot.package_evidence()
    per_rule: list[dict] = []
    for rule in rules:
        finding = next((f for f in findings
                        if str(f.get("rule", f.get("rule_id", ""))) == rule),
                       None)
        bundle = await rule_bundle(snapshot, Path(args.repo_root), alert,
                                   rule, finding, log=log)
        (out_dir / f"bundle-{rule}.txt").write_text(bundle)
        evidence = await snapshot.grounded_evidence(finding)
        head = (f"Alert for AUR package {alert.get('package')} "
                f"({alert.get('old_version')} to {alert.get('new_version')})."
                f"\n\n--- EVIDENCE (gathered by the runtime) ---\n{bundle}\n")

        samples: list[tuple[bool | None, bool | None]] = []
        cites: list[dict] = []
        for sample in range(1, args.samples + 1):
            bad = await ask_json(phase, head + BAD_PRACTICE_QUESTION.replace(
                "%(rule)s", rule), rule,
                keys=("bad_practice_present",), log=log)
            evil = await ask_json(phase, head + MALICIOUS_QUESTION.replace(
                "%(rule)s", rule), rule,
                keys=("malicious_behaviour_present",), log=log)
            samples.append((bad.get("bad_practice_present"),
                            evil.get("malicious_behaviour_present")))
            cites.append({"bad": bad, "evil": evil})
            log(f"[triage {rule} sample {sample}/{args.samples}] "
                f"bad_practice={bad.get('bad_practice_present')} "
                f"malicious={evil.get('malicious_behaviour_present')}")

        # A sample that failed to answer is missing data, not a "no". Use the
        # last sample that answered both questions, and only call it a
        # disagreement when two answered samples actually conflict.
        answered = [(b, e, c) for (b, e), c in zip(samples, cites, strict=False)
                    if b is not None or e is not None]
        chosen: dict = {}
        disputed = False
        if not answered:
            bad_v = evil_v = None
            klass, agree, cited = "uncertain", False, False
            bad_cite = evil_cite = None
            evil_grounded = False
        else:
            bad_v, evil_v, chosen = answered[-1]
            bad_cite = chosen["bad"].get("citation")
            evil_cite = chosen["evil"].get("citation")
            bad_vals = {b for b, _, _ in answered if b is not None}
            evil_vals = {e for _, e, _ in answered if e is not None}
            agree = len(bad_vals) <= 1 and len(evil_vals) <= 1
            klass = class_from_facts(bad_v, evil_v)
            # A TP claim must quote the package. A "not malicious" verdict
            # on an over-threshold alert must likewise rest on a package or
            # alert fact, not on the rule card: that is the rebuttal.
            evil_grounded = grounded_in(evil_cite, evidence)
            need_grounding = evil_v is True or high_score
            cited = citation_ok(bad_cite, evil_v, evil_cite, evil_grounded,
                                need_grounding)
            # A "yes" with no mechanism in the package is a model
            # hallucination (typically a pipe that is not there). It may not
            # become a TP or an alert; it goes to human review instead.
            disputed = evil_v is True and not has_malicious_effect(effect_text)
            if disputed:
                klass, cited = "uncertain", False
                log(f"[triage {rule}] Q2 yes but no execution/effect "
                    "construct in the package evidence; disputed")
        confs = [c["bad"].get("confidence") for c in cites]
        confs += [c["evil"].get("confidence") for c in cites
                  if evil_v is True]
        rank = {"high": 0, "medium": 1, "low": 2}
        confidence = "low" if (not agree or not cited) else (
            {0: "high", 1: "medium", 2: "low"}[max(
                rank.get(str(c), 1) for c in confs or ["medium"])])

        if disputed:
            solve = {"resolution":
                     "Disputed: the malicious answer has no execution, "
                     "exfiltration or persistence mechanism in the package "
                     "evidence. Human review required."}
        else:
            solve = await ask_json(
                phase, head + SOLVE_QUESTION.replace("%(rule)s", rule).replace(
                    "%(klass)s", klass), rule,
                keys=("resolution",), log=log)
        record = {
            "rule_id": rule,
            "class": klass,
            "bad_practice_present": bad_v,
            "malicious_behaviour_present": evil_v,
            "citation": bad_cite,
            "malicious_citation": evil_cite,
            "agree": agree,
            "samples": [[str(b), str(e)] for b, e in samples],
            "cited": cited,
            "malicious_citation_grounded": evil_grounded,
            "confidence": confidence,
            "reasoning": (chosen.get("bad") or {}).get("reasoning"),
            "malicious_reasoning": (chosen.get("evil") or {}).get("reasoning"),
            "resolution": solve.get("resolution"),
            "where": solve.get("where"),
            "tp_twin": solve.get("tp_twin"),
            "ioc_entries": solve.get("ioc_entries") or [],
        }
        per_rule.append(record)
        log(f"[triage {rule}] {klass} ({confidence})"
            + ("" if agree else f" [samples disagree: {samples}]")
            + ("" if cited else " [uncited or ungrounded]"))
        if len(per_rule) >= args.max_rules:
            break
    return {"package": alert.get("package"), "rules": per_rule}


def overall_class(per_rule: list[dict]) -> tuple[str, str]:
    """Overall verdict and a conservative confidence for one package."""

    classes = [r.get("class") for r in per_rule]
    disputed = any(r.get("agree") is False or r.get("cited") is False
                   for r in per_rule)
    if disputed:
        # The malignant/benign axis is the one that must not be guessed.
        overall = "uncertain"
    elif "true_positive" in classes:
        overall = "TP"
    elif classes and all(c == "benign_false_positive" for c in classes):
        overall = "FP"
    elif classes and all(c in ("benign_false_positive",
                               "malicious_false_positive") for c in classes):
        overall = "FP"
    else:
        overall = "uncertain"
    rank = {"high": 0, "medium": 1, "low": 2}
    confs = [rank.get(str(r.get("confidence")), 1) for r in per_rule] or [1]
    confidence = {0: "high", 1: "medium", 2: "low"}[max(confs)]
    return overall, confidence


def render_report(doc: dict, alert: dict, bundle_dir: Path) -> str:
    """Human-readable triage report: the class table and the reasoning."""

    overall, confidence = overall_class(doc["rules"])
    kinds = [r["class"] for r in doc["rules"]]
    lines = [
        f"# Triage: {doc.get('package')}",
        "",
        f"- Alert: {alert.get('alert_slug') or 'n/a'}",
        f"- Transition: {alert.get('old_version')} to {alert.get('new_version')}",
        f"- Verdict: **{overall}** (confidence {confidence})",
        f"- Rules: {len(kinds)} "
        f"({kinds.count('benign_false_positive')} benign, "
        f"{kinds.count('malicious_false_positive')} malicious, "
        f"{kinds.count('true_positive')} true positive)",
        "",
        "| rule | class | confidence | bad practice | malicious "
        "behaviour | samples agree | cited |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in doc["rules"]:
        bad = r.get("bad_practice_present")
        evil = r.get("malicious_behaviour_present")
        agree = r.get("agree")
        lines.append(
            f"| {r['rule_id']} | {r['class']} | {r.get('confidence')} | "
            f"{'yes' if bad else ('no' if bad is False else '?')} | "
            f"{'yes' if evil else ('no' if evil is False else '?')} | "
            f"{'yes' if agree is True else ('no' if agree is False else '?')}"
            f" | {'yes' if r.get('cited') else 'no'} |")
    lines.append("")
    for r in doc["rules"]:
        lines += [
            f"## {r['rule_id']}: {r['class']}",
            "",
            f"- bad practice behind the hit: {r.get('bad_practice_present')}",
            f"- malicious behaviour present: "
            f"{r.get('malicious_behaviour_present')}",
            f"- citation: {r.get('citation')}",
            f"- malicious citation: {r.get('malicious_citation')}",
            f"- reasoning: {r.get('reasoning')}",
            f"- resolution: {r.get('resolution')}",
            f"- where: {r.get('where')}",
            f"- true-positive twin: {r.get('tp_twin')}",
            f"- samples: {r.get('samples')}",
            f"- evidence bundle: {bundle_dir}/bundle-{r['rule_id']}.txt",
            "",
        ]
    if overall == "TP":
        lines += [
            "## What a TP verdict means",
            "",
            "- The malicious evidence is in the rule sections above; the "
            "citation quoted there is the package line the split stage relied "
            "on.",
            "- Escalate to the alert path. Do not open an FP-reproducer PR.",
            "- With --alert, the confirmed-IOC envelope is written to "
            "alert.json next to this report.",
            "",
        ]
    if overall == "FP":
        lines += [
            "## What an FP verdict means",
            "",
            "- A malicious false positive is a bad rule trigger: the fix goes "
            "into the detection shape and ships with its true-positive twin.",
            "- A benign false positive is a real bad practice: the fix belongs "
            "with the packager, or the hit is documented as a known false "
            "positive.",
            "- No package name, maintainer or recipe may appear in detection "
            "logic.",
            "",
        ]
    return "\n".join(lines)


def state_paths(args) -> tuple[Path, Path]:
    """The state dir and the ledger file, created on demand."""

    state = Path(args.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    return state, state / "ledger.jsonl"


def ledger_slugs(ledger: Path) -> set[str]:
    if not ledger.is_file():
        return set()
    out = set()
    for line in ledger.read_text().splitlines():
        try:
            out.add(json.loads(line)["slug"])
        except (ValueError, KeyError):
            continue
    return out


def ledger_append(ledger: Path, entry: dict) -> None:
    with ledger.open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


async def triage_alert(hub: McpHub, args, alert: dict, rules: list[str],
                       findings: list[dict], log=print) -> dict:
    """Triage one package and write its report, verdict and ledger line."""

    state, ledger = state_paths(args)
    slug = alert.get("alert_slug") or "manual"
    package = alert.get("package") or "unknown"
    safe_slug = slug.replace("/", "-")
    out_dir = Path(args.out_dir) / safe_slug / package
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot = Snapshot(hub, alert, log=log)
    doc = await triage_package(hub, snapshot, alert, rules, findings, args,
                               out_dir, log=log)
    overall, confidence = overall_class(doc["rules"])
    doc.update({"alert_slug": slug, "overall": overall,
                "confidence": confidence,
                "score": alert.get("score"),
                "score_threshold": getattr(args, "score_threshold", 20)})
    if overall == "TP" and getattr(args, "alert", False):
        await raise_tp_alert(hub, doc, alert, out_dir, log=log)
    (out_dir / "verdict.json").write_text(json.dumps(doc, indent=2,
                                                     sort_keys=True))
    report = render_report(doc, alert, out_dir)
    (out_dir / "report.md").write_text(report)
    ledger_append(ledger, {
        "slug": slug, "package": package, "overall": overall,
        "confidence": confidence,
        "classes": {r["rule_id"]: r["class"] for r in doc["rules"]},
        "revised": [r["rule_id"] for r in doc["rules"] if r.get("revised")],
        "report": str(out_dir / "report.md"),
        "time": int(time.time()),
    })
    log(f"[triage] {package}: {overall} ({confidence}) -> "
        f"{out_dir / 'report.md'}")
    return doc


async def raise_tp_alert(hub: McpHub, doc: dict, alert: dict,
                         out_dir: Path, log=print) -> dict | None:
    """Render the confirmed-IOC envelope for a TP verdict (opt-in)."""

    rule = next((r for r in doc.get("rules", [])
                 if r.get("class") == "true_positive"), None)
    if rule is None:
        return None
    entries = []
    for item in rule.get("ioc_entries") or []:
        if not isinstance(item, dict) or not item.get("value"):
            continue
        entries.append({
            "type": str(item.get("type") or "domain"),
            "value": str(item["value"]),
            "confidence": str(item.get("confidence") or "medium"),
            "provenance": str(item.get("provenance") or ""),
        })
    result = {
        "kind": "TP",
        "verified": True,
        "package": doc.get("package") or alert.get("package"),
        "version_transition": alert_text(
            f"{alert.get('old_version')} to {alert.get('new_version')}"),
        "rationale": alert_text(rule.get("malicious_reasoning")
                                or rule.get("resolution") or ""),
        "ioc_entries": entries,
    }
    try:
        raw = await hub.call("harness_fp_agent_alert", {"result": result})
    except Exception as exc:
        log(f"[alert] render failed: {exc}")
        return None
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        payload = {"raw": str(raw)}
    if isinstance(payload, dict) and payload.get("error"):
        log(f"[alert] render rejected: {payload['error']}")
        return None
    (out_dir / "alert.json").write_text(json.dumps(payload, indent=2,
                                                   sort_keys=True))
    log(f"[alert] {result['package']}: confirmed-ioc "
        f"({len(entries)} IOC(s)) -> {out_dir / 'alert.json'}")
    return payload


async def triage_live(hub: McpHub, args, slug: str, log=print) -> int:
    """Triage every package of one live alert document."""

    raw = await hub.call("harness_feed_message", {"slug": slug})
    doc = _json_doc(raw) or {}
    packages = doc.get("packages") or []
    rules = [str(r) for r in doc.get("rules") or []]
    payload = doc.get("payload") or {}
    findings = payload.get("findings") or doc.get("findings") or []
    if not packages or not rules:
        log(f"[triage] {slug}: no packages or rules in the document")
        return 1
    for package in packages:
        alert = {"package": package, "alert_slug": slug, "rules": rules,
                 "findings": findings,
                 "score": doc.get("score") or payload.get("score"),
                 "old_version": (doc.get("old_version")
                                 or payload.get("old_version")),
                 "new_version": (doc.get("new_version")
                                 or payload.get("new_version"))}
        await triage_alert(hub, args, alert, rules, findings, log=log)
    return 0


async def watch(args, mcp_config: dict, log=print) -> int:
    """Poll the feed and triage every alert not already in the ledger."""

    state, ledger = state_paths(args)
    log(f"[watch] state {state}; polling every {args.interval}s")
    hub = McpHub(mcp_config, log=log)
    await hub.start()
    if not hub.tools:
        log("[watch] no MCP tools; aborting")
        return 1
    try:
        while True:
            done = ledger_slugs(ledger)
            try:
                raw = await hub.call("harness_feed_search",
                                     {"event": "trustsight.alerts",
                                      "limit": args.feed_limit})
            except Exception as exc:
                log(f"[watch] feed error: {exc}")
                raw = ""
            doc = _json_doc(raw) or {}
            items = doc.get("items") or []
            todo = [it for it in items
                    if it.get("slug") and it["slug"] not in done]
            log(f"[watch] {len(items)} alerts, {len(todo)} to triage")
            for item in reversed(todo):
                try:
                    await triage_live(hub, args, item["slug"], log=log)
                except Exception as exc:
                    log(f"[watch] {item['slug']} failed: {exc}")
                    ledger_append(ledger, {"slug": item["slug"],
                                           "package": None,
                                           "overall": "error",
                                           "time": int(time.time())})
            if args.once:
                return 0
            time.sleep(args.interval)
    finally:
        await hub.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("triage", "fix-pr"), default="triage",
                    help="triage writes reports; fix-pr ships a PR")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--alert-fixture",
                     help="alert JSON (over_threshold entry) to triage")
    src.add_argument("--slug", help="triage one live alert by feed slug")
    ap.add_argument("--watch", action="store_true",
                    help="poll the feed and triage new alerts")
    ap.add_argument("--once", action="store_true",
                    help="with --watch: one poll, then exit")
    ap.add_argument("--interval", type=int, default=300,
                    help="seconds between feed polls (with --watch)")
    ap.add_argument("--feed-limit", type=int, default=20)
    ap.add_argument("--samples", type=int, default=2,
                    help="independent samples of the split stage per rule; "
                         "all must agree or the verdict is uncertain")
    ap.add_argument("--max-rules", type=int, default=99,
                    help="stop after N rules (for quick A/B runs)")
    ap.add_argument("--score-threshold", type=int, default=20,
                    help="an alert at or above this score needs a grounded "
                         "rebuttal before the split may call it not malicious")
    ap.add_argument("--alert", action="store_true",
                    help="for a TP verdict, render the confirmed-IOC alert "
                         "envelope (alert.json); never opens a PR")
    ap.add_argument("--state-dir",
                    default=os.environ.get(
                        "TRIAGE_STATE_DIR",
                        str(Path.home() / ".local/state/trustsight-triage")))
    ap.add_argument("--mcp", default="auto",
                    help="MCP server config JSON; 'auto' resolves the "
                         "workspace layout (TRIAGE_WORKSPACE)")
    ap.add_argument("--workspace",
                    default=os.environ.get(
                        "TRIAGE_WORKSPACE",
                        str(Path.home() / "Documents/GitHub/trustsight")),
                    help="parent holding trustsight/ and trustsight-harness/")
    ap.add_argument(
        "--rbg-repo",
        default=os.environ.get(
            "TRIAGE_RBG_REPO", str(Path.home() / "Documents/GitHub/harness")))
    ap.add_argument("--out-dir", default="/tmp/local-run")
    ap.add_argument("--base-url",
                    default=os.environ.get("TRIAGE_MODEL_BASE_URL",
                                           "http://127.0.0.1:11434/v1"))
    ap.add_argument("--model",
                    default=os.environ.get("TRIAGE_MODEL_NAME",
                                           "ornith-9b-agent:latest"))
    ap.add_argument("--api-key",
                    default=os.environ.get("TRIAGE_MODEL_API_KEY", ""))
    ap.add_argument("--repo-root",
                    default=None,
                    help="watcher checkout repo_read reads from "
                         "(default: <workspace>/trustsight)")
    ap.add_argument("--context", type=int,
                    default=int(os.environ.get("TRIAGE_LOCAL_CONTEXT", "65536")),
                    help="the model's context window; compaction at 40%%")
    ap.add_argument("--explore-steps", type=int, default=22)
    ap.add_argument("--fix-steps", type=int, default=16)
    ap.add_argument("--max-tokens", type=int,
                    default=int(os.environ.get("TRIAGE_LOCAL_MAX_TOKENS", "4096")))
    ap.add_argument("--temperature", type=float,
                    default=float(os.environ.get("TRIAGE_LOCAL_TEMPERATURE", "0.6")))
    ap.add_argument("--reasoning-effort",
                    default=os.environ.get("TRIAGE_LOCAL_REASONING_EFFORT", "none"),
                    help="none disables model thinking; low/medium/high enable it")
    ap.add_argument("--timeout", type=float,
                    default=float(os.environ.get("TRIAGE_LOCAL_TIMEOUT", "900")))
    ap.add_argument("--worktree", default="/tmp/trustsight-triage-work")
    ap.add_argument("--repo-url",
                    default="git@github.com:emiliano-go/trustsight.git")
    ap.add_argument("--repo", default="emiliano-go/trustsight")
    ap.add_argument("--base", default="master")
    ap.add_argument("--no-push", action="store_true",
                    help="branch and commit locally, skip push and PR")
    ap.add_argument("--no-ship", action="store_true",
                    help="do not touch the watcher clone at all")
    args = ap.parse_args()
    if not (args.watch or args.slug or args.alert_fixture):
        ap.error("one of --watch, --slug or --alert-fixture is required")
    if args.mode == "fix-pr" and not args.alert_fixture:
        ap.error("--mode fix-pr needs --alert-fixture")

    if args.repo_root is None:
        args.repo_root = str(Path(args.workspace) / "trustsight")
    if args.mcp == "auto":
        mcp_config = default_mcp_config(
            Path(args.workspace),
            Path(__file__).resolve().parent.parent,
            Path(args.rbg_repo))
    else:
        mcp_config = json.loads(Path(args.mcp).read_text())

    if args.mode == "triage":
        if args.watch:
            return asyncio.run(watch(args, mcp_config))
        if args.slug:
            async def one() -> int:
                hub = McpHub(mcp_config)
                await hub.start()
                try:
                    return await triage_live(hub, args, args.slug)
                finally:
                    await hub.close()
            return asyncio.run(one())
        entry = json.loads(Path(args.alert_fixture).read_text())
        if "over_threshold" in entry:
            entry = entry["over_threshold"][0]
        rules = [str(r) for r in entry.get("rules", [])]
        findings = list(entry.get("findings", []))
        alert = {"package": entry.get("package"),
                 "alert_slug": entry.get("alert_slug"),
                 "old_version": entry.get("old_version"),
                 "new_version": entry.get("new_version"),
                 "score": entry.get("score")}
        for key in ("tree", "diff", "triage", "aur_info", "git_log"):
            if key in entry:
                alert[key] = entry[key]

        async def single() -> int:
            hub = McpHub(mcp_config, alert=alert)
            await hub.start()
            try:
                await triage_alert(hub, args, alert, rules, findings)
            finally:
                await hub.close()
            return 0
        return asyncio.run(single())

    entry = json.loads(Path(args.alert_fixture).read_text())
    if "over_threshold" in entry:
        entry = entry["over_threshold"][0]
    alert = {"package": entry.get("package"),
             "alert_slug": entry.get("alert_slug")}
    rules = [str(r) for r in entry.get("rules", [])]
    findings = list(entry.get("findings", []))
    return asyncio.run(run(args, alert, mcp_config, rules, findings))


if __name__ == "__main__":
    sys.exit(main())
