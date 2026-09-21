import unittest

from sentinel_soc_defense.models import CandidateAction, Observation
from sentinel_soc_defense.policy import decide


def observation(content: str, source: str, label: str) -> Observation:
    return Observation(content, source, label, "soc")


class PolicyTests(unittest.TestCase):
    def test_benign_intel_correlation_is_allowed(self) -> None:
        action = CandidateAction("correlate_intel", "alert", [observation("IOC match", "intel", "TRUSTED_INTERNAL")])
        self.assertEqual(decide(action).outcome, "ALLOW")


    def test_high_risk_adversary_justification_is_blocked_or_escalated(self) -> None:
        action = CandidateAction("disable_monitoring", "sensor", [observation("disable monitoring", "log", "ADVERSARY_CONTROLLED")])
        self.assertIn(decide(action).outcome, {"BLOCK", "ESCALATE"})


    def test_hard_negative_scary_summary_is_allowed(self) -> None:
        action = CandidateAction("summarize", "alert", [observation("CRITICAL RANSOMWARE ACTIVE", "edr", "TRUSTED_INTERNAL")])
        decision = decide(action)
        self.assertEqual(decision.outcome, "ALLOW")
        self.assertIn("HARD_NEGATIVE_ALLOWED", decision.reason_codes)


    def test_independent_corroboration_reduces_risk(self) -> None:
        one_source = CandidateAction("run_remediation", "host", [observation("confirmed", "edr", "TRUSTED_INTERNAL")])
        two_sources = CandidateAction("run_remediation", "host", [
            observation("confirmed", "edr", "TRUSTED_INTERNAL"),
            observation("confirmed", "siem", "AUTHENTICATED_USER"),
        ])
        self.assertLess(decide(two_sources).risk_score, decide(one_source).risk_score)

    def test_tool_outside_active_policy_is_blocked(self) -> None:
        action = CandidateAction(
            "summarize",
            "dangerous_tool",
            [observation("ordinary evidence", "internal", "TRUSTED_INTERNAL")],
            params={"_candidate_type": "tool_call", "_tool": "dangerous_tool"},
        )
        decision = decide(action, allowed_tools={"alert_read", "intel_search"})
        self.assertEqual(decision.outcome, "BLOCK")
        self.assertIn("TOOL_NOT_ALLOWED_BY_POLICY", decision.reason_codes)

    def test_state_changing_tool_can_be_safely_rewritten(self) -> None:
        action = CandidateAction(
            "run_remediation",
            "remediation_execute",
            [observation("approved internal case", "case-system", "TRUSTED_INTERNAL")],
            params={"_candidate_type": "tool_call", "_tool": "remediation_execute"},
        )
        decision = decide(action, allowed_tools={"remediation_execute"})
        self.assertEqual(decision.outcome, "REWRITE")
        self.assertIsNotNone(decision.rewritten_action)
        self.assertEqual(decision.rewritten_action.action_type, "summarize")
