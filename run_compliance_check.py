#!/usr/bin/env python3
"""Write the EU AI Act alignment note for an existing TraceLogger trace."""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinel_soc_defense.compliance import EUAIActAlignment


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", help="Path to a TraceLogger JSONL file")
    parser.add_argument("--output", default="results/eu_ai_act_alignment.md")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(EUAIActAlignment.generate_report(args.trace), encoding="utf-8")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
