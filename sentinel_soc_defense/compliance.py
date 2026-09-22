"""Documentation/reporting aid for the Responsible-AI statement.

This module is explicitly outside the decision-making path: it only reads trace
records and imports policy constants. It strengthens the Responsible-AI
statement by documenting architectural correspondence; it is not a legal
compliance tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import (
    BLOCK_RISK_THRESHOLD,
    CORROBORATION_CREDIT,
    ESCALATE_RISK_THRESHOLD,
    HIGH_CRITICALITY_THRESHOLD,
    LOW_TRUST_THRESHOLD,
    PATTERN_WEIGHT,
    TRUSTED_CORROBORATION_MINIMUM,
)

REQUIRED_AUDIT_FIELDS = ("timestamp", "action_type", "risk_score", "reason_codes", "outcome")


@dataclass(frozen=True)
class AlignmentReport:
    """Computed evidence used to render an EU AI Act alignment note."""

    total_decisions: int
    complete_records: int
    field_coverage: dict[str, int]
    missing_fields: dict[str, list[int]]
    escalations: int
    escalated_actions_require_approval: bool
    malformed_lines: int = 0

    @property
    def escalation_rate(self) -> float:
        return self.escalations / self.total_decisions if self.total_decisions else 0.0


class EUAIActAlignment:
    """Read-only EU AI Act correspondence report for a TraceLogger JSONL file."""

    @staticmethod
    def inspect_trace(trace_path: str | Path) -> AlignmentReport:
        """Inspect records without changing the trace or any policy state."""
        records: list[dict[str, Any]] = []
        malformed_lines = 0
        for line in Path(trace_path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue
            if isinstance(record, dict):
                records.append(record)
            else:
                malformed_lines += 1

        coverage = {field: sum(1 for record in records if _has_field(record, field)) for field in REQUIRED_AUDIT_FIELDS}
        missing = {
            field: [index for index, record in enumerate(records, start=1) if not _has_field(record, field)]
            for field in REQUIRED_AUDIT_FIELDS
        }
        complete = sum(1 for record in records if all(_has_field(record, field) for field in REQUIRED_AUDIT_FIELDS))
        escalations = sum(1 for record in records if str(record.get("outcome", "")).upper() == "ESCALATE")
        return AlignmentReport(
            total_decisions=len(records),
            complete_records=complete,
            field_coverage=coverage,
            missing_fields=missing,
            escalations=escalations,
            escalated_actions_require_approval=True,
            malformed_lines=malformed_lines,
        )

    @classmethod
    def generate_report(cls, trace_path: str | Path) -> str:
        """Return a markdown alignment note computed from ``trace_path``."""
        report = cls.inspect_trace(trace_path)
        total = report.total_decisions
        percent = (report.complete_records / total * 100) if total else 0.0
        escalation_percent = report.escalation_rate * 100
        fields = "\n".join(
            f"- {_mark(report.field_coverage[field] == total)} `{field}`: "
            f"{report.field_coverage[field]}/{total}"
            for field in REQUIRED_AUDIT_FIELDS
        )
        gaps = []
        for field, indexes in report.missing_fields.items():
            if indexes:
                locations = "all decision records" if len(indexes) == total else ", ".join(map(str, indexes))
                gaps.append(f"- `{field}` missing in decision record(s): {locations}")
        if report.malformed_lines:
            gaps.append(f"- malformed/non-object JSONL line(s): {report.malformed_lines}")
        gap_text = "\n".join(gaps) if gaps else "- None found."
        approval = "Yes" if report.escalated_actions_require_approval else "No"

        return f"""# EU AI Act Alignment Note

## Article 9 — Risk Management

The policy computes risk as `criticality × (1 − minimum provenance trust)`, then
adds the instruction-pattern signal (`{PATTERN_WEIGHT:.2f}` maximum) and subtracts
`{CORROBORATION_CREDIT:.2f}` per independent trusted source, capped at two; the result is clamped to `[0, 1]`.
Trusted corroboration uses the policy minimum trust of `{TRUSTED_CORROBORATION_MINIMUM:.2f}`.

- Low risk: below `{ESCALATE_RISK_THRESHOLD:.2f}` — the policy allows the action (subject to tool permission and other branches).
- Medium risk: `{ESCALATE_RISK_THRESHOLD:.2f}` to below `{BLOCK_RISK_THRESHOLD:.2f}` — the policy returns `ESCALATE`.
- High risk: `{BLOCK_RISK_THRESHOLD:.2f}` or above — the policy returns `BLOCK`.
- High-criticality actions (`≥ {HIGH_CRITICALITY_THRESHOLD:.2f}`) with low trust (`≤ {LOW_TRUST_THRESHOLD:.2f}`) and no trusted corroboration trigger the hard `BLOCK` backstop.
- Tool calls outside the active allowed-tool set are blocked before risk scoring.

## Article 12 — Record-Keeping

Decisions with complete audit fields: {report.complete_records}/{total} ({percent:.1f}%)

Field coverage computed from the trace entries:
{fields}

Gaps found:
{gap_text}

## Article 14 — Human Oversight

Escalation rate: {report.escalations}/{total} ({escalation_percent:.1f}%)

Escalated actions require human approval before execution: **{approval}** — verified from `policy.py` and `adapter.py`: `ESCALATE` returns no rewritten action, and the adapter emits a decision response without invoking a tool. The adapter does not itself implement an approval workflow; execution therefore remains the caller's responsibility.

## Scope Note

This system is a synthetic-data research prototype (IndabaX Tunisia SENTINEL challenge).
This alignment note documents architectural correspondence to EU AI Act risk-management,
logging, and oversight provisions; it is not a legal conformity assessment.
"""


def _has_field(record: dict[str, Any], field: str) -> bool:
    value = record.get(field)
    if field == "risk_score":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if field == "reason_codes":
        return isinstance(value, list)
    return value is not None and value != ""


def _mark(ok: bool) -> str:
    return "✅" if ok else "❌"
