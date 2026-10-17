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


def build_prompt(entry: dict, *, verdict_path: str = VERDICT_PATH) -> str:
    """Assemble the prompt string for one over_threshold entry.

    The instruction section deliberately avoids em dashes and " -- " so
    downstream tooling that splits on those markers stays safe.
    """

    package = entry["package"]
    aur_url = entry.get("aur_url", "unknown")
    old_v = entry.get("old_version", "?")
    new_v = entry.get("new_version", "?")
    rules = ", ".join(str(r) for r in entry.get("rules", [])) or "none listed"
    findings = json.dumps(entry.get("findings", []), indent=2, sort_keys=True)
    slug = entry.get("alert_slug") or "none"

    return f"""You are triaging a TrustSight watcher alert for the AUR package
{package!r}. The package moved from version {old_v} to {new_v}.

AUR page: {aur_url}
Alert slug: {slug}
Rules that fired: {rules}

Rule findings (JSON):
{findings}

Task: decide whether this alert is a false positive (FP), a true positive
(TP), or uncertain. Inspect the package build files at the AUR URL and the
findings above. Do not guess; cite what you inspected.

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
- Optional keys alert_slug, version_transition, findings, and ioc_entries
  are allowed when the harness tool output references them; do not invent
  other keys. Use the Alert slug printed above verbatim as alert_slug, or
  omit the key entirely. Include ioc_entries only for a TP verdict with at
  least one entry; never emit it empty.
- findings, when included for an FP verdict, is a non-empty list of
  objects, one per adjudicated rule, each shaped exactly like this (all
  five keys, string values):
  {{"rule_id": "<id from the fired rules above>", "reason": "<what you
  checked and found>", "finding": "<short label>", "false_trigger": "<what
  the rule got wrong>", "fix": "<suggested rule edit, or none>"}}.
  Never bare strings.
- Write version transitions as "old to new", e.g. "0.2.3-1 to 0.2.3-2".
  ASCII only: no em dashes, no double hyphen (--), no ">" characters.

Do the harness tool calls FIRST, in this order, using the verdict object
you decided on:
1. fp_agent_verify with your verdict (it validates and cross-checks the
   package against the AUR and the feed).
2. fp_agent_pr when the verified verdict is FP (it drafts the fix PR),
   then the github tools: create_branch, create_or_update_file for every
   path in the returned files map, and create_pull_request with exactly
   the returned title and body onto the returned branch. Report the PR
   URL.
3. fp_agent_alert when the verified verdict is TP (it publishes the
   confirmed IOC alert).

When the tool calls are done, your FINAL message must be the complete
verdict document and nothing else: one raw JSON object (no markdown
fences, no commentary) with the exact schema above.

Do not modify anything outside the verdict document. Keep every response
string under 4096 characters.
"""
