import time
import unittest

from sentinel_soc_defense.models import CandidateAction
from sentinel_soc_defense.reexecution import MockReExecutor, NotConfiguredError, NullReExecutor


class NullReExecutorTests(unittest.TestCase):
    def test_propose_action_raises_not_configured(self) -> None:
        with self.assertRaises(NotConfiguredError) as context:
            NullReExecutor().propose_action_with_masked_task([], [], "neutral task")
        self.assertIn("No AgentReExecutor configured", str(context.exception))


class MockReExecutorTests(unittest.TestCase):
    def test_returns_fixture_for_matching_scenario_key(self) -> None:
        action = CandidateAction("run_remediation", "host-1")
        executor = MockReExecutor(fixture={"key": action}, scenario_key="key")
        self.assertIs(executor.propose_action_with_masked_task([], [], "task"), action)

    def test_returns_none_for_unknown_scenario_key(self) -> None:
        executor = MockReExecutor(fixture={}, scenario_key="missing")
        self.assertIsNone(executor.propose_action_with_masked_task([], [], "task"))

    def test_latency_seconds_actually_delays(self) -> None:
        executor = MockReExecutor(fixture={}, scenario_key="key", latency_seconds=0.05)
        started = time.monotonic()
        executor.propose_action_with_masked_task([], [], "task")
        self.assertGreaterEqual(time.monotonic() - started, 0.05)


if __name__ == "__main__":
    unittest.main()
