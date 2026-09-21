"""Render a TraceLogger JSONL session as a clean, video-readable markdown table."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _cell(value: object) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ").strip()


def render_markdown(path: Path) -> str:
    rows: list[str] = [
        "| # | Action | Target | Risk Score | Outcome | Reason Codes | Justifying Source (trust level) |",
        "|---:|---|---|---:|---|---|---|",
    ]
    if not path.exists():
        return "Trace file not found: " + str(path)
    for number, record in enumerate(
        (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line), 1
    ):
        sources = record.get("observations", []) + record.get("memory", [])
        provenance = "; ".join(
            f"{item.get('source', 'memory')} ({item.get('trust_label', 'unknown')})" for item in sources
        ) or "none recorded"
        reasons = ", ".join(record.get("reason_codes", [])) or "none"
        rows.append(
            "| " + " | ".join(
                _cell(value)
                for value in (
                    number,
                    record.get("action_type", "unknown"),
                    record.get("target", "unknown"),
                    f"{float(record.get('risk_score', 0.0)):.2f}",
                    record.get("outcome", "unknown"),
                    reasons,
                    provenance,
                )
            ) + " |"
        )
    return "\n".join(rows)


def _color_table(markdown: str) -> str:
    colors = {"ALLOW": "\033[32m", "BLOCK": "\033[31m", "ESCALATE": "\033[33m", "REWRITE": "\033[34m"}
    reset = "\033[0m"
    for outcome, color in colors.items():
        markdown = markdown.replace(f"| {outcome} |", f"| {color}{outcome}{reset} |")
    return markdown


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m sentinel_soc_defense.render_trace TRACE.jsonl")
    table = render_markdown(Path(sys.argv[1]))
    print(_color_table(table) if sys.stdout.isatty() else table)


if __name__ == "__main__":
    main()
