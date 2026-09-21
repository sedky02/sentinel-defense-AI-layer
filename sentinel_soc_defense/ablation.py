"""Run four honest policy ablations over the same simulator scenario batch."""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path

from .batch_runner import run_batch

CONFIGURATIONS = {
    "full_policy": [],
    "no_instruction_detector": ["--disable-pattern"],
    "no_corroboration_backstop": ["--disable-corroboration-backstop"],
    "no_memory_trust_inheritance": ["--disable-memory-inheritance"],
}


def rates(rows: list[dict[str, str]]) -> tuple[str, str, str]:
    scored = [row for row in rows if row["pass_fail"] in {"PASS", "FAIL"}]
    attacks = [row for row in scored if row.get("hard_negative", "false").lower() != "true"]
    negatives = [row for row in scored if row not in attacks]
    rate = lambda values: "N/A" if not values else f"{sum(r['pass_fail'] == 'PASS' for r in values)/len(values):.2%}"
    attack_rate, hard_negative_rate = rate(attacks), rate(negatives)
    fp = "N/A" if not negatives else f"{sum(r['pass_fail'] == 'FAIL' for r in negatives)/len(negatives):.2%}"
    return attack_rate, hard_negative_rate, fp


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("scenario_dir", type=Path); parser.add_argument("--results", type=Path, default=Path("results/ablation_results.csv")); parser.add_argument("--base-port", type=int, default=8090)
    args = parser.parse_args(); output: list[dict[str, str]] = []
    for number, (name, flags) in enumerate(CONFIGURATIONS.items()):
        trace = Path("results") / f"ablation_{name}.jsonl"; trace.parent.mkdir(exist_ok=True)
        if trace.exists(): trace.unlink()
        port = args.base_port + number
        server = subprocess.Popen([sys.executable, "-m", "sentinel_soc_defense.adapter", "--port", str(port), "--trace", str(trace), *flags])
        try:
            time.sleep(.3)
            rows = run_batch(args.scenario_dir, f"http://127.0.0.1:{port}", trace, Path("results") / f"scenario_{name}.csv")
        finally:
            server.terminate(); server.wait(timeout=3)
        attack, hard_negative, false_positive = rates(rows)
        output.append({"configuration": name, "attack_pass_rate": attack, "hard_negative_pass_rate": hard_negative, "false_positive_rate": false_positive, "scenarios": str(len(rows))})
    args.results.parent.mkdir(parents=True, exist_ok=True)
    with args.results.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0])); writer.writeheader(); writer.writerows(output)
    print("\nAblation comparison")
    for row in output: print("  {configuration:30} attacks={attack_pass_rate:>7} hard-negative={hard_negative_pass_rate:>7} false-positive={false_positive_rate:>7}".format(**row))
    print(f"\nWrote {args.results}")


if __name__ == "__main__": main()
