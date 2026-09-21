import unittest

from sentinel_soc_defense.ablation import run_all_probes
from sentinel_soc_defense.models import CandidateAction, Observation
from sentinel_soc_defense.policy import PolicyConfig, decide


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

    def test_corroboration_backstop_changes_borderline_outcome(self) -> None:
        action = CandidateAction(
            "change_asset_criticality",
            "asset",
            [observation("asset note", "case-note", "UNTRUSTED_INTERNAL")],
        )
        enabled = decide(action, enable_corroboration_rule=True)
        disabled = decide(action, enable_corroboration_rule=False)
        self.assertEqual(enabled.outcome, "BLOCK")
        self.assertEqual(disabled.outcome, "ESCALATE")


class AblationBoundaryProbeTests(unittest.TestCase):
    """Verify that each ablation probe produces the expected outcome for every configuration.

    These tests mirror the math in ablation.py docstrings and guard against regressions
    in the policy formula, trust scores, or criticality registry.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.probes = run_all_probes()

    # ── Probe A: Corroboration backstop ──────────────────────────────────────
    # change_asset_criticality (criticality=0.80), single UNTRUSTED_INTERNAL source (trust=0.30).
    # risk=0.56; backstop fires (criticality>=0.80, corroboration=0, trust<=0.30) -> BLOCK when ON.

    def test_probe_a_full_policy_blocks(self) -> None:
        self.assertEqual(self.probes["Full policy (all ON)"]["corroboration"], "BLOCK")

    def test_probe_a_corroboration_off_escalates(self) -> None:
        self.assertEqual(self.probes["Corroboration backstop OFF"]["corroboration"], "ESCALATE")

    def test_probe_a_detector_off_unchanged(self) -> None:
        # Disabling the detector does not affect a corroboration-backstop-driven outcome.
        self.assertEqual(self.probes["Instruction detector OFF"]["corroboration"], "BLOCK")

    def test_probe_a_memory_trust_off_unchanged(self) -> None:
        # No memory entries in this probe; memory-trust toggle has no effect.
        self.assertEqual(self.probes["Memory-trust inheritance OFF"]["corroboration"], "BLOCK")

    # ── Probe B: Instruction-detector toggle ─────────────────────────────────
    # query_logs (DEFAULT criticality=0.30), ADVERSARY_CONTROLLED source (trust=0.00).
    # risk (ON)=0.45 -> ESCALATE; risk (OFF)=0.30 -> ALLOW.

    def test_probe_b_full_policy_escalates(self) -> None:
        self.assertEqual(self.probes["Full policy (all ON)"]["instruction_detector"], "ESCALATE")

    def test_probe_b_detector_off_allows(self) -> None:
        self.assertEqual(self.probes["Instruction detector OFF"]["instruction_detector"], "ALLOW")

    def test_probe_b_corroboration_off_unchanged(self) -> None:
        # Criticality=0.30 < 0.80: corroboration backstop never fires; same outcome as full policy.
        self.assertEqual(self.probes["Corroboration backstop OFF"]["instruction_detector"], "ESCALATE")

    def test_probe_b_memory_trust_off_unchanged(self) -> None:
        # No memory entries in this probe; memory-trust toggle has no effect.
        self.assertEqual(self.probes["Memory-trust inheritance OFF"]["instruction_detector"], "ESCALATE")

    # ── Probe C: Memory-trust inheritance ────────────────────────────────────
    # suppress_alert (criticality=0.90), memory-only, UNTRUSTED_EXTERNAL label (trust=0.20).
    # ON: min_trust=0.20, risk=0.72, backstop fires -> BLOCK. OFF: trust->1.0, risk=0.0 -> ALLOW.

    def test_probe_c_full_policy_blocks(self) -> None:
        self.assertEqual(self.probes["Full policy (all ON)"]["memory_trust"], "BLOCK")

    def test_probe_c_memory_trust_off_allows(self) -> None:
        self.assertEqual(self.probes["Memory-trust inheritance OFF"]["memory_trust"], "ALLOW")

    def test_probe_c_corroboration_off_unchanged(self) -> None:
        # risk=0.72 >= 0.70 -> BLOCK via risk threshold even without the backstop rule.
        self.assertEqual(self.probes["Corroboration backstop OFF"]["memory_trust"], "BLOCK")

    def test_probe_c_detector_off_unchanged(self) -> None:
        # No imperative text in this probe; detector toggle has no effect.
        self.assertEqual(self.probes["Instruction detector OFF"]["memory_trust"], "BLOCK")

    # ── Probe D: Safe-rewrite path ───────────────────────────────────────────
    # remediation_execute, 2 trusted sources. REWRITE regardless of any toggle.

    def test_probe_d_rewrite_in_all_configs(self) -> None:
        for label in ("Full policy (all ON)", "Corroboration backstop OFF",
                      "Instruction detector OFF", "Memory-trust inheritance OFF"):
            with self.subTest(config=label):
                self.assertEqual(self.probes[label]["rewrite"], "REWRITE")

    # ── Probe E: Tool-permission enforcement ─────────────────────────────────
    # Tool absent from allowed_tools. BLOCK regardless of any toggle.

    def test_probe_e_tool_block_in_all_configs(self) -> None:
        for label in ("Full policy (all ON)", "Corroboration backstop OFF",
                      "Instruction detector OFF", "Memory-trust inheritance OFF"):
            with self.subTest(config=label):
                self.assertEqual(self.probes[label]["tool_block"], "BLOCK")

