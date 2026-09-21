"""Structured JSONL audit logging for defense decisions."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import CandidateAction, Decision


class TraceLogger:
    def __init__(self, path: str | Path = "sentinel_decisions.jsonl") -> None:
        self.path = Path(path)

    def log(self, action: CandidateAction, decision: Decision) -> None:
        record = {
            "action_type": action.action_type,
            "target": action.target,
            "outcome": decision.outcome,
            "risk_score": decision.risk_score,
            "reason_codes": decision.reason_codes,
            "explanation": decision.explanation,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def summary(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                counts[json.loads(line)["outcome"]] += 1
        result = dict(counts)
        print(result)
        return result
