"""One focused ablation: remove the corroboration/hard-rule backstop."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from .batch_runner import run_batch


def _run(name: str, scenario_dir: Path, disabled: bool, port: int) -> list[dict[str, str]]:
    trace = Path("results") / f"ablation_{name}.jsonl"
    trace.parent.mkdir(parents=True, exist_ok=True)
    flags = ["--disable-corroboration-backstop"] if disabled else []
    server = subprocess.Popen([sys.executable, "-m", "sentinel_soc_defense.adapter", "--port", str(port), "--trace", str(trace), *flags])
    try:
        time.sleep(0.4)
        return run_batch(scenario_dir, f"http://127.0.0.1:{port}", trace, Path("results") / f"scenario_{name}.csv")
    finally:
        server.terminate()
        server.wait(timeout=5)


def _counts(rows: list[dict[str, str]]) -> tuple[int, int, int, int, list[str]]:
    attacks = [row for row in rows if row.get("attack_present") == "true"]
    hard_negatives = [row for row in rows if row.get("attack_present") == "false"]
    caught = [row for row in attacks if row.get("attack_decision") == "caught"]
    missed = [row for row in attacks if row.get("attack_decision") != "caught"]
    passed = [row for row in hard_negatives if row["pass_fail"] == "PASS"]
    overblocked = [row for row in hard_negatives if row["pass_fail"] == "FAIL"]
    return len(caught), len(missed), len(passed), len(overblocked), [row["scenario_name"] for row in missed]


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare corroboration backstop ON versus OFF.")
    parser.add_argument("scenario_dir", nargs="?", type=Path, default=Path("/tmp/sentinel_starter_kit/scenarios/public/soc"))
    parser.add_argument("--results", type=Path, default=Path("results/ablation_results.md"))
    args = parser.parse_args()
    configurations = [("Full policy (corroboration ON)", "on", False, 8091), ("Corroboration rule OFF", "off", True, 8092)]
    summary: list[tuple[str, tuple[int, int, int, int, list[str]]]] = []
    for label, name, disabled, port in configurations:
        summary.append((label, _counts(_run(name, args.scenario_dir, disabled, port))))

    def ratio(value: int, total: int) -> str: return f"{value}/{total}"
    rows = []
    for label, (caught, missed, passed, overblocked, _) in summary:
        attacks_total, negatives_total = caught + missed, passed + overblocked
        rows.append(f"| {label} | {ratio(caught, attacks_total)} | {ratio(missed, attacks_total)} | {ratio(passed, negatives_total)} |")
    baseline_missed = set(summary[0][1][4]); off_missed = set(summary[1][1][4]); additional = sorted(off_missed - baseline_missed)
    interpretation = [
        "### Interpretation",
        f"The corroboration backstop was compared on the same attack and hard-negative scenario set in both runs.",
        f"With the rule OFF, {len(additional)} additional attack scenario(s) were missed" + (f": {', '.join(additional)}." if additional else "."),
        f"Hard-negative pass counts were {summary[0][1][2]} with the rule ON and {summary[1][1][2]} with it OFF; lower values indicate over-blocking.",
    ]
    content = "# Corroboration-rule ablation\n\n| Configuration | Attacks caught | Attacks missed | Hard negatives passed (not over-blocked) |\n|---|---:|---:|---:|\n" + "\n".join(rows) + "\n\n" + "\n".join(interpretation) + "\n"
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(content, encoding="utf-8"); print(content, end="")


if __name__ == "__main__": main()
