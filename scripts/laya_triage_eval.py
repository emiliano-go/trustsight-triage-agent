"""Can Laya triage a TrustSight alert?

The 9B runtime sees a ~21 KB evidence bundle and answers two cited questions.
Laya sees ~1.5 KB, cannot cite, and answers the same two questions as `noul`.
This script measures whether that is enough to agree with the recorded ledger.

    python scripts/laya_triage_eval.py --limit 5     # smoke
    python scripts/laya_triage_eval.py               # all ledger alerts

Evidence comes from the same harness MCP tools the 9B runtime uses, so the
comparison is about the model's reading, not about a different data source.
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import importlib.util
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRUSTSIGHT = ROOT.parent / "trustsight"
WORK = ROOT / ".work"

_spec = importlib.util.spec_from_file_location(
    "local_agent", ROOT / "scripts" / "local_agent.py")
la = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(la)

SUSPICIOUS = re.compile(
    r"curl|wget|base64|eval\b|\bbash\b|\bsh\b|systemctl|useradd|chmod|chown"
    r"|install\s*=|source\s*=|python|perl|\bnc\b|crontab|authorized_keys"
    r"|/dev/tcp|\.install|prepare\s*\(|package\s*\(", re.IGNORECASE)

Q_BAD = ("Does this package show a bad packaging practice? Answer yes only if the "
         "package itself does something undesirable but not malicious.")
Q_EVIL = ("Does this package contain malicious behaviour: execution of fetched code, "
          "exfiltration, or persistence?")

VERDICT = {"benign_false_positive": "BFP", "malicious_false_positive": "MFP",
           "true_positive": "TP", "uncertain": "uncertain"}


# --- evidence ---------------------------------------------------------------

def findings_of(dossier: str) -> list[dict]:
    """Findings inside the fp_triage dossier, whatever its exact nesting."""
    try:
        doc = json.loads(dossier)
    except (json.JSONDecodeError, TypeError):
        return []

    out: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if "rule" in node or "rule_id" in node:
                out.append({k: node.get(k) for k in
                            ("rule", "rule_id", "line", "file", "reason", "detail")
                            if node.get(k) is not None})
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    return out[:8]


def compact_view(dossier: str, pkgbuild: str, limit: int = 1600) -> str:
    """A ~1.5 KB view: what fired, where, and the suspicious lines around it."""
    findings = findings_of(dossier)
    heads = []
    for finding in findings:
        rule = finding.get("rule") or finding.get("rule_id")
        where = " ".join(str(finding.get(k))
                         for k in ("file", "line") if finding.get(k))
        why = str(finding.get("reason") or finding.get("detail") or "")[:180]
        heads.append(f"- {rule} {where}: {why}".strip())

    lines = pkgbuild.splitlines()
    picks: list[int] = []
    for index, line in enumerate(lines):
        if SUSPICIOUS.search(line):
            picks.append(index)
    wanted: set[int] = set(range(min(12, len(lines))))
    for index in picks[:6]:
        wanted.update(range(max(0, index - 2), min(len(lines), index + 3)))
    excerpt = "\n".join(lines[index] for index in sorted(wanted))

    text = ("Findings:\n" + ("\n".join(heads) or "- (none)") +
            "\n\nPKGBUILD excerpt:\n" + excerpt)
    return text[:limit]


async def gather(rows: list[dict], cache_path: Path, log=print) -> dict[str, dict]:
    """One compact view per (slug, package), through the harness MCP."""
    cached: dict[str, dict] = {}
    if cache_path.exists():
        for line in cache_path.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cached[f"{row['slug']}|{row['package']}"] = row

    config = la.default_mcp_config(TRUSTSIGHT, ROOT, ROOT.parent / "harness")
    hub = la.McpHub(config, log=lambda *a, **k: None)
    await hub.start()
    try:
        with cache_path.open("a") as out:
            for row in rows:
                slug = row["slug"]
                for package in row["packages"]:
                    key = f"{slug}|{package}"
                    if key in cached:
                        continue
                    alert = {"alert_slug": slug, "package": package}
                    snapshot = la.Snapshot(hub, alert, log=lambda *a, **k: None)
                    try:
                        dossier = await snapshot.triage()
                        pkgbuild = await snapshot.pkgbuild()
                    except Exception as error:  # noqa: BLE001 - keep going
                        log(f"  {key}: fetch failed: {error}")
                        continue
                    view = compact_view(dossier, pkgbuild)
                    record = {"slug": slug, "package": package,
                              "view": view, "chars": len(view)}
                    cached[key] = record
                    out.write(json.dumps(record) + "\n")
                    out.flush()
                    log(f"  {key}: {len(view)} chars")
    finally:
        await hub.close()
    return cached


# --- model ------------------------------------------------------------------

def ask(base_url: str, state: dict, question: str) -> float:
    body = {"state": state,
            "questions": {"q": {"type": "noul", "instructions": question}}}
    request = urllib.request.Request(
        f"{base_url}/v1/systemone", data=json.dumps(body).encode(),
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return float(json.loads(response.read())["answers"]["q"].get("noul") or 0.0)


def predict(view: str, package: str, base_url: str) -> dict:
    state = {"task": f"Triage the AUR package {package}", "answer": view}
    bad = ask(base_url, state, Q_BAD)
    evil = ask(base_url, state, Q_EVIL)
    klass = la.class_from_facts(bad > 0.5, evil > 0.5)
    return {"bad": round(bad, 3), "evil": round(evil, 3),
            "class": VERDICT[klass], "internal": klass}


# --- report -----------------------------------------------------------------

def predict_all(records: dict[str, dict], cache_path: Path, base_url: str,
                log=print) -> dict[str, dict]:
    """Predictions cached per (slug, package): the Laya arm is the slow part."""
    cached: dict[str, dict] = {}
    if cache_path.exists():
        for line in cache_path.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cached[f"{row['slug']}|{row['package']}"] = row
    pending = [key for key in records if key not in cached]
    log(f"  predictions: {len(cached)} cached, {len(pending)} to run")
    with cache_path.open("a") as out:
        for index, key in enumerate(pending, 1):
            record = records[key]
            try:
                predicted = predict(record["view"], record["package"], base_url)
            except Exception as error:  # noqa: BLE001 - keep going
                log(f"  {key}: predict failed: {error}")
                continue
            row = {"slug": record["slug"], "package": record["package"], **predicted}
            cached[key] = row
            out.write(json.dumps(row) + "\n")
            out.flush()
            if index % 25 == 0:
                log(f"    {index}/{len(pending)}")
    return cached


def report(rows: list[dict], records: dict[str, dict],
           predictions: dict[str, dict]) -> dict:
    table = []
    for row in rows:
        for package in row["packages"]:
            key = f"{row['slug']}|{package}"
            if key not in predictions:
                continue
            truth = row["verdicts"].get(package, "uncertain")
            pred = predictions[key]
            table.append({"slug": row["slug"], "package": package,
                          "truth": truth, "pred": pred["class"],
                          "bad": pred["bad"], "evil": pred["evil"],
                          "agree": truth == pred["class"]})
    n = len(table) or 1
    agree = sum(1 for row in table if row["agree"]) / n
    # 97% of this ledger is MFP, so agreement alone is not evidence:
    # always-MFP already scores ~0.97.
    majority = collections.Counter(row["truth"] for row in table).most_common(1)[0][0]
    majority_agree = sum(1 for row in table if row["truth"] == majority) / n
    bfp = [row for row in table if row["truth"] == "BFP"]
    bfp_caught = sum(1 for row in bfp if row["pred"] == "BFP")
    # MFP is the class this corpus is about.
    mfp = [row for row in table if row["truth"] == "MFP"]
    mfp_agree = sum(1 for row in mfp if row["pred"] == "MFP") / (len(mfp) or 1)
    false_alerts = [row for row in table
                    if row["pred"] == "TP" and row["truth"] != "TP"]
    confusion: dict[str, int] = {}
    for row in table:
        key = f"{row['truth']}->{row['pred']}"
        confusion[key] = confusion.get(key, 0) + 1
    return {"packages": len(table), "agreement": round(agree, 3),
            "always_mfp_agreement": round(majority_agree, 3),
            "agreement_lift": round(agree - majority_agree, 3),
            "mfp_recall": round(mfp_agree, 3), "mfp_support": len(mfp),
            "bfp_support": len(bfp), "bfp_caught": bfp_caught,
            "false_alerts": len(false_alerts), "confusion": confusion,
            "rows": table}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger", default=str(TRUSTSIGHT / "alert-triage" / "ledger.jsonl"))
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out", default=str(WORK / "laya-triage-results.json"))
    args = parser.parse_args()

    WORK.mkdir(exist_ok=True)
    rows = [json.loads(line) for line in open(args.ledger)]
    if args.limit:
        rows = rows[:args.limit]
    print(f"ledger alerts: {len(rows)}", flush=True)

    records = asyncio.run(gather(rows, WORK / "laya-triage-views.jsonl"))
    predictions = predict_all(records, WORK / "laya-triage-preds.jsonl", args.base_url)
    result = report(rows, records, predictions)
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=1))
    print(f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
