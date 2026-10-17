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

    return f"""You are triaging a TrustSight watcher alert for the AUR package
{package!r}. The package moved from version {old_v} to {new_v}.

AUR page: {aur_url}
Rules that fired: {rules}

Rule findings (JSON):
{findings}

Task: decide whether this alert is a false positive (FP), a true positive
(TP), or uncertain. Inspect the package build files at the AUR URL and the
findings above. Do not guess; cite what you inspected.

Write your verdict as JSON to {verdict_path}. It must match this schema
exactly, with no extra keys:

{_VERDICT_SCHEMA_JSON}

Rules for the verdict file:
- verdict is one of FP, TP, uncertain; confidence is one of high, medium,
  low.
- evidence maps each fired rule to what you checked and what you found.
- proposed_changes is only for FP verdicts: the rule edit that would have
  suppressed this alert, or an empty object if none applies.

After writing the verdict file, call the harness tools in this order:
1. fp_agent_verify with your verdict (it validates and cross-checks the
   package against the AUR and the feed).
2. fp_agent_pr when the verified verdict is FP (it drafts the fix PR).
3. fp_agent_alert when the verified verdict is TP (it publishes the
   confirmed IOC alert).

Do not modify anything outside {verdict_path}. Keep every response string
under 4096 characters.
"""
