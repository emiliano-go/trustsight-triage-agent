#!/usr/bin/env bash
# A/B the four TP fixtures at samples=1 and samples=2, then print the matrix.
#
#   scripts/ab_tp_fixtures.sh [out-dir]     (default: /tmp/ab-tp)
#
# Needs the local model endpoint (default http://127.0.0.1:11434/v1, override
# with TRIAGE_MODEL_BASE_URL) and the MCP servers scripts/local_agent.py
# starts by default. Expect ~30-45 min for all eight runs.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-/tmp/ab-tp}"
mkdir -p "$out"
: > "$out/run.log"

for samples in 1 2; do
  for name in alert_tp_synthetic alert_tp_synthetic_benign \
              alert_tp_historical alert_tp_historical_benign; do
    dir="$out/s${samples}-$name"
    echo "===== samples=$samples fixture=$name =====" | tee -a "$out/run.log"
    uv run python scripts/local_agent.py --mode triage \
      --alert-fixture "tests/fixtures/$name.json" --samples "$samples" --alert \
      --out-dir "$dir/reports" --state-dir "$dir/state" 2>&1 \
      | tee -a "$out/run.log" \
      | grep --line-buffered -aE '^\[triage|^\[alert|^\[bundle'
  done
done

python3 - "$out" <<'PY'
import json, pathlib, sys
for run in sorted(pathlib.Path(sys.argv[1]).glob("s*")):
    verdicts = list((run / "reports").glob("*/*/verdict.json"))
    if not verdicts:
        print(f"{run.name:45} NO VERDICT")
        continue
    verdict = json.loads(verdicts[0].read_text())
    rule = verdict["rules"][0]
    alert = verdicts[0].parent / "alert.json"
    iocs = ([e["value"] for e in json.loads(alert.read_text())["ioc_entries"]]
            if alert.exists() else [])
    print(f"{run.name:45} {verdict['overall']:5} {verdict['confidence']:6} "
          f"class={rule['class']:22} Q1={rule['bad_practice_present']} "
          f"Q2={rule['malicious_behaviour_present']} "
          f"cited={rule['cited']} alert={iocs}")
PY
