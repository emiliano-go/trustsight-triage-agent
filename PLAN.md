# Plan — triage agent, next round (2026-11-16)

## What I checked today

| check | result |
|---|---|
| `uv run pytest -q` | 25 passed, 0.58 s |
| `uv run ruff check .` | clean |
| Ollama | up; `ornith-9b-agent:latest` (4.6 GB) present |
| MCP servers | harness 59 tools, aur 2, rbg 25 (86 total) |
| End-to-end fixture | `alert_tp_synthetic` → R001 **TP, high**, `alert.json` with 1 IOC, ~70 s |
| Runtime state | watcher **stopped**; 1 alert ever triaged (2026-10-16); 1 report on disk |

Two findings from the check:

1. **`--samples` defaults to 2**, but `README.md` says "`samples=1` and
   `samples=2` agree, so 1 is the default-cost choice". Every alert currently
   costs double. Decide: change the default to 1, or correct the README.
2. The watcher has not run since 16 October. Whatever the feed produced since
   is unprocessed.

## The real gap

The agent works. It is not **running**, not **delivering**, and not **measured on
real alerts**. Everything below is one of those three.

## What already exists (found 2026-11-16)

`~/Documents/GitHub/trustsight/alert-triage/` is a working triage pipeline
written by dsh-totem's `/triage` command — the same job this agent does:

- `ledger.jsonl` — **40 real alerts**, each with per-package verdicts
  (`BFP | MFP | TP | uncertain`), counts, a report path and a one-line "why";
- `reports/` — one Markdown report per alert, with a per-package table;
- `queue-*.json` — the untriaged feed window handed to one run;
- the MFP → rule-shape → regression-test loop, already running weekly:
  PR #179 (eleven MFP shapes, 2026-11-14), PR #193 (2026-11-16), and
  `fix/alert-triage-2026-11-17-mfps` (pushed, unmerged, "clear four false
  positives", ships `tests/regressions/test_alert_triage_2026_11_17.py`).

So the labelled evaluation set the plan wanted to build by hand already exists,
and the output vocabulary the local agent uses
(`benign_false_positive | malicious_false_positive | true_positive`) is a
one-line mapping to it.

**Caveat: 0 TPs in 40 alerts.** The ledger measures false-positive precision,
not malware recall. The four synthetic/historical fixtures remain the only TP
signal, and any TP claim for the local agent has to be measured there.

## Rejected before P0: Laya as the triage model (done 2026-11-16)

Tried the cheap model in the triage seat, evidence and all: 303 packages from
the ledger, a 1.6 KB compact view (the ceiling of a 512-token state), the
runtime's own two questions and class mapping. Result: **0 of 11 BFP caught,
58 false alerts, agreement 0.667 against a 0.964 always-MFP baseline.**
Full record in [`LAYA-TRIAGE.md`](LAYA-TRIAGE.md).

It is structural — the 21 KB bundle does not fit in 512 tokens, and a model that
cannot quote evidence cannot ground a TP. The 9B stays.

## P0 — verify the twin (0:15)

Run `alert_tp_synthetic_benign` through the same command and confirm it is not
an alert. The TP path is proven; the false-alarm path is the one that costs
trust. Record both timings.

## P1 — guard tests (1–2 h, no model)

`src/triage_agent` and `scripts/local_agent.py` carry the safety properties,
and only `test_split.py` / `test_aur_mcp.py` exist. Add deterministic tests for
the pure functions — this is the cheapest insurance in the repo:

- `has_malicious_effect`: true for `curl … | bash`, `base64 -d | sh`, an
  exfil POST; false for `curl -o`, a build command, a bare URL.
- `grounded_in` / `citation_ok`: a TP needs a package quote; an over-threshold
  alert needs grounding for "not malicious"; an empty citation fails.
- `class_from_facts`: the four cells, plus `None` staying `uncertain`.
- the disputed path: Q2 yes + no mechanism → `uncertain`, never TP/alert.
- the samples path: disagreeing samples → `uncertain`; a missing sample is not
  a "no".
- `_MALICIOUS_EFFECT` is a floor: a new pattern must be added with a test.

Bar: deleting any guard makes a test fail.

## P2 — replay the ledger, not a hand-built corpus (2 h)

Run the local agent over the 40 recorded alerts (`--alert <slug>`, or the
already-generated `queue-*.json`), with `--alert` **off** and a temp state dir,
then compare per package against the recorded verdicts:

- agreement and confusion (`BFP | MFP | TP | uncertain`) per package;
- the MFP calls it gets wrong, with the rule and the ledger's "why";
- wall time per alert, and whether any guard disputing fires.

Bar: **≥ 80% per-package agreement on MFP vs non-MFP**, and no verdict that
would have produced an alert for a package the ledger calls benign. TP recall is
*not* measurable on this corpus and must not be claimed from it.

Then freeze the 5–8 most informative **disagreements** as fixtures with their
evidence trees — the interesting cases are the ones the model and the ledger
disagree on, not the ones they share.

## P3 — delivery (2–3 h)

`alert.json` is rendered and dropped. The loop is open, and the workspace
already has the sink (`trustsight-feed`, ntfy). Options:

- publish to the feed (durable, matches the envelope's intended consumer), or
- ntfy for immediacy, with the feed as the record.

Requirements, in order: **opt-in flag** (`--publish`), **idempotent by slug**
(one publish per alert, ever), **never publish `uncertain` or disputed**, and a
dry-run that prints the payload. The envelope itself stays unchanged.

Before any of that: **converge the ledger schema**. The local agent writes its
own shape (`classes`, `overall`, `package`); `/triage` writes
`{slug, triaged_at, packages, verdicts, counts, report, summary}`. Emit the
second, map `benign_false_positive → BFP`, `malicious_false_positive → MFP`,
`true_positive → TP`, and dedupe by slug so one ledger serves both pipelines.

## P4 — escalation (3 h, optional)

The README is right that the honest small-model system escalates, and right
that 4B + 9B do not fit in 8 GB together. So the design is staged:

1. run the 4B on the P2 fixtures and the real backlog, count `uncertain` and
   disputed;
2. if those are uncommon, run 4B by default and pay the model swap only for
   them (measure the swap — expected 10–20 s);
3. if the swap costs more than it saves, stay on the 9B and record why.

Bar: fewer wall-seconds per alert at equal TP precision on the frozen set.

## P5 — make it a service (0:30, or fold into P2)

`bin/triage-agent start` is `setsid nohup`, which survives a logout but not a
reboot or an OOM kill. A user systemd unit with `Restart=on-failure` and the
same env file is the difference between "exists" and "runs".

## Order and budget

| phase | time | why this order |
|---|---|---|
| P0 | 0:15 | proves the false-alarm path before changing anything |
| P1 | 1–2 h | locks the guards that everything else relies on |
| P2 | 2 h | replays the 40-alert ledger; produces the real fixtures |
| P5 | 0:30 | keeps it running while P3/P4 happen |
| P3 | 2–3 h | closes the loop, only after the backlog shows what would ship |
| P4 | 3 h | optimisation; needs the fixtures from P2 |

Total ≈ 8–11 h, shippable incrementally: P0+P1+P5 is a day's work and turns the
agent from "demo" into "running".

## Decisions needed

1. `--samples`: 1 (docs say it is the default) or 2 (code says it is)?
2. Delivery sink: feed, ntfy, or both?
3. Escalation: worth the swap, or stay 9B-only?

## Risks

- **False negatives are invisible.** Every guard rejects false positives; nothing
  measures a missed TP. P2 is the only place that can see one, and only by hand.
- **Six GB of VRAM.** Anything else on the GPU spills the model to CPU (~3×).
- **Real PKGBUILDs are bigger than the fixtures.** A 21 KB bundle is ~7.2k
  tokens; the context ladder says 16k is the safe floor. Watch for truncation
  warnings on the backlog run.
