import json
import tempfile
import unittest
from pathlib import Path

from sentinel_soc_defense.compliance import EUAIActAlignment


def record(outcome: str = "ALLOW", *, timestamp: bool = True) -> dict:
    result = {
        "action_type": "summarize",
        "risk_score": 0.1,
        "reason_codes": [],
        "outcome": outcome,
    }
    if timestamp:
        result["timestamp"] = "2026-09-22T00:00:00Z"
    return result


class ComplianceTests(unittest.TestCase):
    def write_trace(self, records: list[dict]) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        with handle:
            for item in records:
                handle.write(json.dumps(item) + "\n")
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_missing_audit_field_is_caught(self) -> None:
        report = EUAIActAlignment.inspect_trace(self.write_trace([record(), record(timestamp=False)]))
        self.assertEqual(report.complete_records, 1)
        self.assertEqual(report.field_coverage["timestamp"], 1)
        self.assertEqual(report.missing_fields["timestamp"], [2])

    def test_escalation_rate_is_arithmetically_correct(self) -> None:
        report = EUAIActAlignment.inspect_trace(self.write_trace([
            record("ALLOW"), record("ESCALATE"), record("BLOCK"), record("ESCALATE"),
        ]))
        self.assertEqual(report.escalations, 2)
        self.assertEqual(report.total_decisions, 4)
        self.assertAlmostEqual(report.escalation_rate, 0.5)


if __name__ == "__main__":
    unittest.main()
