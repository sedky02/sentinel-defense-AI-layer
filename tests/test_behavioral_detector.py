import unittest

from sentinel_soc_defense.behavioral_detector import evaluate_behavioral_signal
from sentinel_soc_defense.models import CandidateAction, Observation
from sentinel_soc_defense.reexecution import MockReExecutor, NullReExecutor


def action(action_type: str, target: str, **params) -> CandidateAction:
    return CandidateAction(action_type, target, params=params)


class BehavioralSimilarityTests(unittest.TestCase):
    def test_same_tool_same_target_triggers(self) -> None:
        original = action("close_incident", "INC-101")
        masked = action("close_incident", "INC-101")
        reexecutor = MockReExecutor(fixture={"k": masked}, scenario_key="k")
        signal = evaluate_behavioral_signal(original, reexecutor, [], [])
        self.assertTrue(signal.triggered)
        self.assertEqual(signal.similarity_score, 1.0)
        self.assertEqual(signal.reason, "SAME_TOOL_SAME_TARGET")

    def test_same_tool_same_critical_arg_triggers(self) -> None:
        original = action("run_remediation", "host-a", incident_id="INC-9")
        masked = action("run_remediation", "host-b", incident_id="INC-9")
        reexecutor = MockReExecutor(fixture={"k": masked}, scenario_key="k")
        signal = evaluate_behavioral_signal(original, reexecutor, [], [])
        self.assertTrue(signal.triggered)
        self.assertEqual(signal.similarity_score, 1.0)

    def test_partial_overlap_logged_not_triggered(self) -> None:
        original = action("run_remediation", "host-a")
        masked = action("run_remediation", "host-b")
        reexecutor = MockReExecutor(fixture={"k": masked}, scenario_key="k")
        signal = evaluate_behavioral_signal(original, reexecutor, [], [])
        self.assertFalse(signal.triggered)
        self.assertEqual(signal.similarity_score, 0.4)
        self.assertEqual(signal.reason, "PARTIAL_OVERLAP_BENIGN")

    def test_different_tool_no_signal(self) -> None:
        original = action("close_incident", "INC-101")
        masked = action("summarize", "INC-101")
        reexecutor = MockReExecutor(fixture={"k": masked}, scenario_key="k")
        signal = evaluate_behavioral_signal(original, reexecutor, [], [])
        self.assertFalse(signal.triggered)
        self.assertEqual(signal.similarity_score, 0.0)
        self.assertEqual(signal.reason, "DIFFERENT_TOOL_PROPOSED")

    def test_no_masked_action_is_healthy(self) -> None:
        original = action("close_incident", "INC-101")
        reexecutor = MockReExecutor(fixture={}, scenario_key="missing")
        signal = evaluate_behavioral_signal(original, reexecutor, [], [])
        self.assertFalse(signal.triggered)
        self.assertEqual(signal.similarity_score, 0.0)
        self.assertEqual(signal.reason, "NO_MASKED_ACTION_PROPOSED")
        self.assertIsNone(signal.masked_action)


class BehavioralUnavailabilityTests(unittest.TestCase):
    def test_not_configured_reexecutor_yields_unavailable_signal(self) -> None:
        original = action("close_incident", "INC-101")
        signal = evaluate_behavioral_signal(original, NullReExecutor(), [], [])
        self.assertFalse(signal.triggered)
        self.assertTrue(signal.reason.startswith("BEHAVIORAL_SIGNAL_UNAVAILABLE"))

    def test_timeout_yields_unavailable_signal_promptly(self) -> None:
        original = action("close_incident", "INC-101")
        slow_executor = MockReExecutor(fixture={}, scenario_key="k", latency_seconds=5.0)
        import time

        started = time.monotonic()
        signal = evaluate_behavioral_signal(original, slow_executor, [], [], timeout_seconds=0.1)
        elapsed = time.monotonic() - started
        self.assertFalse(signal.triggered)
        self.assertTrue(signal.reason.startswith("BEHAVIORAL_SIGNAL_UNAVAILABLE"))
        self.assertLess(elapsed, 1.0)  # proves the timeout actually cuts off, not just waits


if __name__ == "__main__":
    unittest.main()
