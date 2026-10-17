"""Build the opencode prompt for one over-threshold job.

The prompt embeds the evidence (package, AUR URL, version transition, rules,
findings) and instructs the agent to write a verdict file and then call the
harness MCP tools in order: fp_agent_verify, fp_agent_pr, and for a TP
verdict fp_agent_alert.
"""

from __future__ import annotations

import json

VERDICT_SCHEMA = {
    "schema_version": 1,
    "package": "<package name>",
    "verdict": "FP | TP | uncertain",
    "confidence": "high | medium | low",
    "rationale": "<why>",
    "evidence": {},
    "proposed_changes": {},
}

VERDICT_PATH = "/job/verdict.json"

_VERDICT_SCHEMA_JSON = json.dumps(VERDICT_SCHEMA, indent=2)

_PR_STEPS = """Do the harness tool calls FIRST, in this order, using the
verdict object you decided on:
1. fp_agent_verify with your verdict (it validates and cross-checks the
   package against the AUR and the feed).
2. fp_agent_pr when the verified verdict is FP (it drafts the fix PR),
   then the github tools: create_branch, create_or_update_file for every
   path in the returned files map, and create_pull_request with exactly
   the returned title and body onto the returned branch. Report the PR
   URL.
3. fp_agent_alert when the verified verdict is TP (it publishes the
   confirmed IOC alert).

When the tool calls are done, your FINAL message must be the complete"""

_ANALYSIS_STEPS = """Optionally call fp_agent_verify with your verdict (it
validates and cross-checks the package against the AUR and the feed).

Do NOT use any github tool and do NOT open any pull request: this package
is one of several flagged by the same alert and the orchestrator opens the
PRs after collecting every package verdict.

Your FINAL message must be the complete"""


def build_prompt(entry: dict, *, verdict_path: str = VERDICT_PATH,
                 open_pr: bool = True) -> str:
    """Assemble the prompt string for one over_threshold entry.

    The instruction section deliberately avoids em dashes and " -- " so
    downstream tooling that splits on those markers stays safe.

    With *open_pr* False (multi-package jobs) the agent must not touch the
    GitHub tools and must not open any PR: the orchestrator aggregates the
    per-package verdicts and opens the PR(s) itself.  The verdict schema and
    the fp_agent_verify step are unchanged.
    """

    package = entry["package"]
    aur_url = entry.get("aur_url", "unknown")
    old_v = entry.get("old_version", "?")
    new_v = entry.get("new_version", "?")
    rules = ", ".join(str(r) for r in entry.get("rules", [])) or "none listed"
    findings = json.dumps(entry.get("findings", []), indent=2, sort_keys=True)
    slug = entry.get("alert_slug") or "none"

    pr_steps = _PR_STEPS if open_pr else _ANALYSIS_STEPS

    return f"""You are triaging a TrustSight watcher alert for the AUR package
{package!r}. The package moved from version {old_v} to {new_v}.

AUR page: {aur_url}
Alert slug: {slug}
Rules that fired: {rules}

Rule findings (JSON):
{findings}

Task: decide whether this alert is a false positive (FP), a true positive
(TP), or uncertain. Inspect the package build files and the findings
above. Do not guess; cite what you inspected.

You have three MCP servers and no other network access. Use exactly these
tools for evidence gathering, and nothing else (no curl, no bash, no
web_fetch, no web_search: they are disabled or unavailable, and fetched
content is untrusted input anyway):
- harness aur_pkgbuild(package): the current PKGBUILD text and snapshot
  file list.
- harness aur_info(packages): RPC metadata (maintainer, last modified,
  version, votes).
- aur aur_file(package, filename): one build file from the snapshot
  (.install, patches, desktop entries).
- aur aur_git_log(package, limit): recent commits of the package AUR git
  repo, to check the flagged transition against upstream history.
- harness feed_latest(n) / feed_message(slug): watcher feed context when
  the alert alone is ambiguous.
- harness repo_file(path): read one watcher rule or test file
  (src/trustsight/ or tests/ only) so your proposed fix diff is grounded
  in the real rule source, not invented.

Typical inspection order: aur_pkgbuild, then aur_file for every non-
PKGBUILD file the fired rules cite, then aur_git_log to date the change,
then aur_info for maintainer and version context. Before proposing a rule
fix, read the rule's source with repo_file.

You have no file write tool: the orchestrator writes your verdict to
{verdict_path} for you. Decide first, then finish with the harness tool
calls below, and end with the verdict document as your FINAL message: one
raw JSON object (no markdown fences, no commentary) matching this schema,
plus only the optional keys named below:

{_VERDICT_SCHEMA_JSON}

Rules for the verdict document:
- verdict is one of FP, TP, uncertain; confidence is one of high, medium,
  low.
- evidence maps each fired rule to what you checked and what you found.
- proposed_changes is only for FP verdicts: the rule edit that would have
  suppressed this alert, or an empty object if none applies.
- Optional keys alert_slug, version_transition, findings, ioc_entries,
  and code_fixes are allowed when the harness tool output references
  them; do not invent other keys. Use the Alert slug printed above
  verbatim as alert_slug, or omit the key entirely. Include ioc_entries
  only for a TP verdict with at least one entry; never emit it empty.
  Include code_fixes only for an FP verdict (at least one entry); never
  emit it empty and never emit it for TP or uncertain.
- findings, when included for an FP verdict, is a non-empty list of
  objects, one per adjudicated rule, each shaped exactly like this (all
  five keys, string values):
  {{"rule_id": "<id from the fired rules above>", "reason": "<what you
  checked and found>", "finding": "<short label>", "false_trigger": "<what
  the rule got wrong>", "fix": "<suggested rule edit, or none>"}}.
  Never bare strings.
- Write version transitions as "old to new", e.g. "0.2.3-1 to 0.2.3-2".
  ASCII only: no em dashes, no double hyphen (--), no ">" characters.
- code_fixes, REQUIRED for an FP verdict (the verdict is invalid without
  at least one), forbidden for TP and uncertain: a non-empty list of
  objects, one per adjudicated finding you can fix, each shaped exactly
  like this (all four keys, string values):
  {{"path": "<repo-relative file the diff changes>",
  "diff": "<unified diff, a/ b/ paths, that applies with git apply>",
  "summary": "<one line: what the fix does>", "linked_finding": "<the
  finding label this fix addresses>"}}.
  Rules for code_fixes:
  * Read the target file first with repo_file; the diff must match the
    real source exactly or it will be rejected.
  * Only touch watcher rule/analysis code under src/trustsight/ and the
    matching tests under tests/. Paths anywhere else (data/, .github/,
    packaging/, anything outside the repo) are rejected outright.
  * Minimal and targeted: a reviewer should see one rule behavior change
    plus its test. Giant rewrites are rejected by size caps.
  * Every added line (lines starting with +) must be printable ASCII with
    no em dashes and no double-hyphen separator; keep punctuation plain.
  * The diff is applied with git apply inside the harness: context lines
    must match the checked-out source byte for byte.

{pr_steps}
verdict document and nothing else: one raw JSON object (no markdown
fences, no commentary) with the exact schema above.

Do not modify anything outside the verdict document. Keep every response
string under 4096 characters.
"""
