"""TrustSight triage agent, local-model edition.

The runtime is ``scripts/local_agent.py``: one local model over the
TrustSight MCP servers. The triage route asks two narrow cited questions per
rule, maps the answers to a class in code, writes ``report.md`` and
``verdict.json``, and (with ``--alert``) renders the confirmed-IOC envelope
for a TP. ``triage_agent.aur_mcp`` is the AUR MCP server the runtime starts;
``triage_agent.verdicts`` and ``triage_agent.fix_pr`` back the optional
FP-reproducer PR path.

No opencode, no job containers, no remote model gateway.
"""

__version__ = "0.1.0"
