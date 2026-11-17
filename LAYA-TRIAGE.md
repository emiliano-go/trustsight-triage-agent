# Laya as the triage model — tried, rejected (2026-11-16)

Question: can Laya (300M, non-autoregressive, 512-token state) decide a
TrustSight alert's class instead of the 9B? Tested against the recorded ledger,
not against hand-built cases.

## Method

`scripts/laya_triage_eval.py`, evidence through the same harness MCP tools the
9B runtime uses (`fp_triage` + `aur_pkgbuild`):

- per package, a **compact view** (~1.6 KB, the most Laya can ever see):
  the fired rules with their reason/line, plus the PKGBUILD's first lines and
  ±2 lines around each suspicious construct;
- two `noul` questions — bad practice? malicious? — mapped with the runtime's
  own `class_from_facts`, so only the reading differs, not the mapping;
- compared per package against `alert-triage/ledger.jsonl`.

303 packages, 600 model calls, ~13 minutes on CPU.

## Result

| | |
|---|---:|
| agreement with the ledger | **0.667** |
| always-MFP baseline | **0.964** |
| lift over the constant | **−0.297** |
| BFP packages caught | **0 of 11** |
| **false alerts raised** (TP on a package the ledger calls benign) | **58** (57 MFP, 1 BFP) |
| MFP → BFP (false bad-practice accusation) | 33 |
| MFP recall | 0.692 |

Score spread: `evil` mean 0.341 (0.0–0.994), `bad` mean 0.409 (0.0–0.992) —
the model varies, but the variation does not track the evidence. 58 packages
cross `evil > 0.5` and every one of them becomes a TP, i.e. an alert.

## Why this is structural, not a bad prompt

1. **The evidence does not fit.** A rule bundle is ~21 KB (~7k tokens). The 9B
   needs 8k minimum and 16–32k to be safe (`agent/README.md` context ladder);
   Laya's state is capped at 512 tokens (1024 on the multilingual checkpoint).
   The 1.6 KB view is already at the ceiling — no prompt can give it the bundle.
2. **It cannot cite.** A TP is only accepted when the quoted text appears in
   the fetched evidence. Laya returns probabilities, so every TP it emits is
   ungrounded and would have to be rejected by the guard anyway.
3. **The class that matters is the rare one.** 97% of the ledger is MFP; the
   discriminative question is the 11 BFPs, where Laya scored 0. Any model that
   says "MFP" every time beats it on agreement and raises no false alerts.

## Verdict

Do not use Laya as the triage model. The 9B stays. The useful outcome of this
run is the compact-view harness: it can serve as the *escalation pre-filter*
question later (is this alert obviously routine?), but not as the verdict.
