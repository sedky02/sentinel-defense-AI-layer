"""Render screen-recordable static HTML from a TraceLogger JSONL file."""

from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter
from pathlib import Path


def render(trace_path: Path, output: Path, results_csv: Path | None = None) -> Path:
    records = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line] if trace_path.exists() else []
    counts = Counter(record["outcome"] for record in records)
    family_summary = "No batch results available."
    if results_csv and results_csv.exists():
        groups: dict[str, list[str]] = {}
        with results_csv.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle): groups.setdefault(row["attack_family"], []).append(row["pass_fail"])
        family_summary = " · ".join(f"{html.escape(k)}: {sum(x == 'PASS' for x in v)}/{len(v)} pass" for k, v in groups.items()) or family_summary
    cards = []
    for index, record in enumerate(records, 1):
        provenance = "".join(f"<li><b>{html.escape(item.get('source', 'memory'))}</b> <span class='trust'>{html.escape(item.get('trust_label','unknown'))}</span><br>{html.escape(item.get('content',''))}</li>" for item in record.get("observations", []) + record.get("memory", [])) or "<li>No justifications recorded</li>"
        score = float(record.get("risk_score", 0)) * 100
        cards.append(f"<article class='card {html.escape(record['outcome'])}'><div class='top'><h2>{index}. {html.escape(record['action_type'])}</h2><span class='badge'>{html.escape(record['outcome'])}</span></div><p class='target'>Target: {html.escape(record.get('target','unknown'))}</p><div class='gauge'><i style='width:{score:.0f}%'></i></div><p class='score'>Risk score: <b>{score:.0f}%</b></p><p class='codes'>{html.escape(' · '.join(record.get('reason_codes', [])) or 'No reason codes')}</p><details open><summary>Provenance: observations and memory</summary><ul>{provenance}</ul></details><p class='explanation'>{html.escape(record.get('explanation',''))}</p></article>")
    page = f"""<!doctype html><html><head><meta charset='utf-8'><title>SENTINEL SOC Defense Trace</title><style>
body{{font-family:Arial,sans-serif;background:#101722;color:#f4f7fb;margin:0;padding:32px;max-width:1100px;margin:auto;font-size:18px}}h1{{font-size:38px;margin-bottom:8px}}.summary{{background:#192536;padding:20px;border-radius:12px;font-size:22px}}.card{{margin:20px 0;padding:24px;border-radius:12px;background:#192536;border-left:12px solid #888}}.top{{display:flex;justify-content:space-between;align-items:center}}h2{{font-size:27px;margin:0}}.badge{{font-weight:bold;font-size:22px;padding:9px 16px;border-radius:8px}}.ALLOW{{border-color:#30bf73}}.ALLOW .badge{{background:#17643d}}.BLOCK{{border-color:#f05050}}.BLOCK .badge{{background:#852d2d}}.ESCALATE{{border-color:#f2bd3e}}.ESCALATE .badge{{background:#805f13}}.REWRITE{{border-color:#4f9cff}}.REWRITE .badge{{background:#215999}}.gauge{{height:20px;background:#0d121b;border-radius:9px;overflow:hidden}}.gauge i{{display:block;height:100%;background:linear-gradient(90deg,#30bf73,#f2bd3e,#f05050)}}.trust,.codes{{color:#a8caff;font-weight:bold}}li{{margin:13px 0;line-height:1.35}}summary{{font-size:21px;font-weight:bold}}.explanation{{color:#c8d3df}}</style></head><body><h1>SENTINEL SOC Defense — Decision Trace</h1><div class='summary'><b>{len(records)} actions</b> · ALLOW {counts['ALLOW']} · BLOCK {counts['BLOCK']} · ESCALATE {counts['ESCALATE']} · REWRITE {counts['REWRITE']}<br><br><b>Pass rate by attack family:</b> {family_summary}</div>{''.join(cards) or '<p>No trace records found.</p>'}</body></html>"""
    output.write_text(page, encoding="utf-8"); return output


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--trace", type=Path, default=Path("sentinel_decisions.jsonl")); parser.add_argument("--output", type=Path, default=Path("dashboard.html")); parser.add_argument("--results", type=Path, default=Path("results/scenario_results.csv")); args = parser.parse_args(); print(render(args.trace, args.output, args.results).resolve())


if __name__ == "__main__": main()
