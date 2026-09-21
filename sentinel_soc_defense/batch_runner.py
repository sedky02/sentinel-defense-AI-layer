"""Batch-run official SENTINEL scenarios and score published outcome artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any


def is_soc_or_hard_negative(path: Path) -> bool:
    """Use declarative YAML fields only; never use a scenario ID or expected result."""
    text = path.read_text(encoding="utf-8")
    domain = re.search(r"^domain:\s*(\w+)", text, flags=re.MULTILINE)
    no_attack = re.search(r"^attack:\s*\n\s*present:\s*false\b", text, flags=re.MULTILINE)
    return bool((domain and domain.group(1).lower() == "soc") or no_attack)


def scenario_files(directory: Path) -> list[Path]:
    return [path for path in sorted((*directory.rglob("*.yaml"), *directory.rglob("*.yml"))) if is_soc_or_hard_negative(path)]


def row_from_outcome(outcome: dict[str, Any], status: str) -> dict[str, str]:
    decisions = outcome.get("decisions", [])
    # The simulator itself grades success conditions and security properties. This
    # consumes those generic machine-checkable results instead of scenario labels.
    secure = not outcome.get("attack_success", False) and not outcome.get("critical_violation", False)
    task_ok = bool(outcome.get("task_success", False))
    hard_negative = bool(outcome.get("hard_negative", False))
    passed = secure and task_ok
    actual = "SECURE_TASK_COMPLETED" if passed else ("SECURITY_VIOLATION" if not secure else "TASK_NOT_COMPLETED")
    return {"scenario_name": str(outcome.get("scenario_id", "unknown")), "attack_family": str(outcome.get("attack_family", "none")),
            "difficulty_level": str(outcome.get("difficulty", "n/a")),
            "expected_secure_outcome_class": "task_success_without_attack_or_critical_violation",
            "actual_outcome": actual, "risk_score": str(decisions[-1].get("risk_score", "") if decisions else ""),
            "reason_codes": ";".join(decisions[-1].get("reason_codes", []) if decisions else []),
            "pass_fail": "PASS" if passed else "FAIL", "hard_negative": str(hard_negative).lower(), "simulator_status": status}


def run_batch(scenario_dir: Path, defense_url: str, trace: Path, results_path: Path, *, artifacts: Path = Path("results/simulator_artifacts"), model: str = "mock") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for scenario in scenario_files(scenario_dir):
        command = ["sentinel", "run", "--scenario", str(scenario), "--defense-url", defense_url, "--model", model, "--artifacts", str(artifacts), "--no-timeline", "--json"]
        try:
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
        except FileNotFoundError:
            rows.append({"scenario_name": scenario.stem, "attack_family": "unknown", "difficulty_level": "unknown", "expected_secure_outcome_class": "unavailable", "actual_outcome": "NO_SIMULATOR", "risk_score": "", "reason_codes": "", "pass_fail": "MANUAL_REVIEW", "hard_negative": "unknown", "simulator_status": "simulator_not_installed"}); continue
        if completed.returncode:
            rows.append({"scenario_name": scenario.stem, "attack_family": "unknown", "difficulty_level": "unknown", "expected_secure_outcome_class": "unavailable", "actual_outcome": "SIMULATOR_ERROR", "risk_score": "", "reason_codes": "", "pass_fail": "MANUAL_REVIEW", "hard_negative": "unknown", "simulator_status": f"simulator_exit_{completed.returncode}"}); continue
        try:
            outcome = json.loads(completed.stdout)["outcome"]
            rows.append(row_from_outcome(outcome, "ran"))
        except (json.JSONDecodeError, KeyError, TypeError):
            rows.append({"scenario_name": scenario.stem, "attack_family": "unknown", "difficulty_level": "unknown", "expected_secure_outcome_class": "unavailable", "actual_outcome": "UNPARSEABLE_SIMULATOR_OUTPUT", "risk_score": "", "reason_codes": "", "pass_fail": "MANUAL_REVIEW", "hard_negative": "unknown", "simulator_status": "unparseable"})
    results_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["scenario_name", "attack_family", "difficulty_level", "expected_secure_outcome_class", "actual_outcome", "risk_score", "reason_codes", "pass_fail", "hard_negative", "simulator_status"]
    with results_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    return rows


def print_summary(rows: list[dict[str, str]]) -> None:
    for field in ("attack_family", "difficulty_level"):
        groups: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows: groups[row[field]].append(row)
        print(f"\nPass rate by {field}:")
        for name, group in sorted(groups.items()):
            scored = [row for row in group if row["pass_fail"] in {"PASS", "FAIL"}]
            rate = "manual review only" if not scored else f"{sum(row['pass_fail'] == 'PASS' for row in scored) / len(scored):.0%}"
            print(f"  {name}: {rate} ({len(group)} scenarios)")


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("scenario_dir", type=Path); parser.add_argument("--defense-url", default="http://127.0.0.1:8080"); parser.add_argument("--trace", type=Path, default=Path("sentinel_decisions.jsonl")); parser.add_argument("--results", type=Path, default=Path("results/scenario_results.csv")); parser.add_argument("--artifacts", type=Path, default=Path("results/simulator_artifacts")); parser.add_argument("--model", default="mock")
    args = parser.parse_args(); rows = run_batch(args.scenario_dir, args.defense_url, args.trace, args.results, artifacts=args.artifacts, model=args.model); print_summary(rows); print(f"\nWrote {args.results}")


if __name__ == "__main__": main()
