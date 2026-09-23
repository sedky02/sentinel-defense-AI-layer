"""Structured JSONL audit logging for defense decisions."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import CandidateAction, Decision


class TraceLogger:
    def __init__(self, path: str | Path = "sentinel_decisions.jsonl") -> None:
        self.path = Path(path)

    def log(self, action: CandidateAction, decision: Decision, *, session_id: str = "local", metadata: dict | None = None) -> None:
        record = {
            "session_id": session_id,
            "action_type": action.action_type,
            "target": action.target,
            "outcome": decision.outcome,
            "risk_score": decision.risk_score,
            "reason_codes": decision.reason_codes,
            "explanation": decision.explanation,
            "rewritten_action": (
                {"action_type": decision.rewritten_action.action_type,
                 "target": decision.rewritten_action.target,
                 "params": decision.rewritten_action.params}
                if decision.rewritten_action is not None else None
            ),
            "observations": [
                {"content": item.content, "source": item.source, "trust_label": item.trust_label,
                 "sensitivity": item.sensitivity}
                for item in action.justifying_observations
            ],
            "memory": [
                {"content": item.content, "trust_label": item.trust_label,
                 "derived_from": item.derived_from, "written_at": item.written_at}
                for item in action.justifying_memory
            ],
            "behavioral_signal": (
                {"triggered": decision.behavioral_signal.triggered,
                 "similarity_score": decision.behavioral_signal.similarity_score,
                 "reason": decision.behavioral_signal.reason,
                 "latency_seconds": decision.behavioral_signal.latency_seconds}
                if decision.behavioral_signal is not None else None
            ),
            "payload_sensitivity": decision.payload_sensitivity,
            "effective_criticality": decision.effective_criticality,
            "intent_drift_penalty": decision.intent_drift_penalty,
            "sensitivity_findings": decision.sensitivity_findings,
            "metadata": metadata or {},
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
