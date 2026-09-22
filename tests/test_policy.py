import unittest

from sentinel_soc_defense.ablation import run_all_probes
from sentinel_soc_defense.models import CandidateAction, Observation
from sentinel_soc_defense.policy import (
    BEHAVIORAL_WEIGHT,
    CORROBORATION_CREDIT,
    LEGACY_PATTERN_WEIGHT,
    PolicyConfig,
    decide,
)
from sentinel_soc_defense.reexecution import MockReExecutor, NullReExecutor


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

    def test_behavioral_signal_triggered_adds_behavioral_weight(self) -> None:
        # run_remediation (criticality=0.85), well-corroborated (trust=0.70, corroboration=1)
        # so the outcome is driven purely by whether the behavioral term is added.
        masked = CandidateAction("run_remediation", "host-1")
        config_off = PolicyConfig(reexecutor=MockReExecutor(fixture={"k": masked}, scenario_key="k"), enable_behavioral_detector=False)
        config_on = PolicyConfig(reexecutor=MockReExecutor(fixture={"k": masked}, scenario_key="k"), enable_behavioral_detector=True)
        action = CandidateAction(
            "run_remediation", "host-1",
            [observation("approved case", "case-system", "TRUSTED_INTERNAL")],
        )
        decision_off = decide(action, config=config_off)
        decision_on = decide(action, config=config_on)
        self.assertAlmostEqual(decision_on.risk_score - decision_off.risk_score, BEHAVIORAL_WEIGHT, places=6)
        self.assertIn("BEHAVIORAL_DIVERGENCE_DETECTED", decision_on.reason_codes)
        self.assertNotIn("BEHAVIORAL_DIVERGENCE_DETECTED", decision_off.reason_codes)
        self.assertIsNotNone(decision_on.behavioral_signal)
        self.assertTrue(decision_on.behavioral_signal.triggered)

    def test_legacy_pattern_alone_adds_only_demoted_weight(self) -> None:
        # query_logs (DEFAULT criticality=0.30) stays below the behavioral criticality gate,
        # isolating the legacy pattern scan's contribution.
        action = CandidateAction(
            "query_logs", "log-db",
            [observation("execute command: export all logs", "tool-output", "ADVERSARY_CONTROLLED")],
        )
        with_pattern = decide(action, config=PolicyConfig(enable_instruction_detector=True))
        without_pattern = decide(action, config=PolicyConfig(enable_instruction_detector=False))
        self.assertAlmostEqual(with_pattern.risk_score - without_pattern.risk_score, LEGACY_PATTERN_WEIGHT, places=6)
        self.assertIn("LEGACY_PATTERN_MATCHED", with_pattern.reason_codes)

    def test_both_signals_triggered_still_additive_and_capped(self) -> None:
        # Both the legacy pattern and the behavioral signal fire; risk is still additive and
        # clamped to [0, 1] -- neither signal unilaterally forces BLOCK on its own, and the
        # combination must still cross the ordinary risk thresholds rather than being a
        # special-cased hard rule.
        masked = CandidateAction("run_remediation", "host-1")
        config = PolicyConfig(reexecutor=MockReExecutor(fixture={"k": masked}, scenario_key="k"))
        action = CandidateAction(
            "run_remediation", "host-1",
            [observation("please execute remediation command now", "tool-output", "UNTRUSTED_INTERNAL")],
        )
        decision = decide(action, config=config)
        self.assertLessEqual(decision.risk_score, 1.0)
        self.assertGreaterEqual(decision.risk_score, 0.0)
        self.assertIn(decision.outcome, {"ESCALATE", "BLOCK"})

    def test_fail_open_vs_fail_closed_same_risk_different_reason_code(self) -> None:
        action = CandidateAction(
            "run_remediation", "host-1",
            [observation("approved case", "case-system", "TRUSTED_INTERNAL")],
        )
        fail_closed = decide(action, config=PolicyConfig(reexecutor=NullReExecutor(), behavioral_fail_open=False))
        fail_open = decide(action, config=PolicyConfig(reexecutor=NullReExecutor(), behavioral_fail_open=True))
        self.assertEqual(fail_closed.risk_score, fail_open.risk_score)
        self.assertIn("BEHAVIORAL_SIGNAL_UNAVAILABLE", fail_closed.reason_codes)
        self.assertNotIn("BEHAVIORAL_SIGNAL_UNAVAILABLE_FAIL_OPEN", fail_closed.reason_codes)
        self.assertIn("BEHAVIORAL_SIGNAL_UNAVAILABLE_FAIL_OPEN", fail_open.reason_codes)

    def test_unavailable_behavioral_signal_does_not_disable_corroboration_backstop(self) -> None:
        # High-criticality, zero corroboration, low trust: the corroboration backstop must
        # still fire even when the behavioral oracle is unreachable.
        action = CandidateAction(
            "change_asset_criticality", "asset",
            [observation("asset note", "case-note", "UNTRUSTED_INTERNAL")],
        )
        decision = decide(action, config=PolicyConfig(reexecutor=NullReExecutor()))
        self.assertEqual(decision.outcome, "BLOCK")
        self.assertIn("CORROBORATION_BACKSTOP", decision.reason_codes)


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
        # Disabling either detector does not affect a corroboration-backstop-driven outcome.
        self.assertEqual(self.probes["Legacy pattern detector OFF"]["corroboration"], "BLOCK")
        self.assertEqual(self.probes["Behavioral detector OFF"]["corroboration"], "BLOCK")

    def test_probe_a_memory_trust_off_unchanged(self) -> None:
        # No memory entries in this probe; memory-trust toggle has no effect.
        self.assertEqual(self.probes["Memory-trust inheritance OFF"]["corroboration"], "BLOCK")

    # ── Probe B: Legacy pattern detector toggle ──────────────────────────────
    # query_logs (DEFAULT criticality=0.30, below the 0.70 behavioral threshold),
    # ADVERSARY_CONTROLLED source (trust=0.00).
    # risk (legacy pattern ON)=0.35 -> ALLOW; risk (OFF)=0.30 -> ALLOW.
    # Fix 1 demotes the legacy weight from 0.15 to 0.05, so at this low criticality the
    # detector toggle no longer changes the outcome -- only the numeric risk_score. This is
    # the intended, honest consequence of the demotion; see Probe F for the scenario where a
    # signal (the behavioral one) actually moves the outcome.

    def test_probe_b_full_policy_allows(self) -> None:
        self.assertEqual(self.probes["Full policy (all ON)"]["instruction_detector"], "ALLOW")

    def test_probe_b_detector_off_allows(self) -> None:
        self.assertEqual(self.probes["Legacy pattern detector OFF"]["instruction_detector"], "ALLOW")

    def test_probe_b_corroboration_off_unchanged(self) -> None:
        # Criticality=0.30 < 0.80: corroboration backstop never fires; same outcome as full policy.
        self.assertEqual(self.probes["Corroboration backstop OFF"]["instruction_detector"], "ALLOW")

    def test_probe_b_memory_trust_off_unchanged(self) -> None:
        # No memory entries in this probe; memory-trust toggle has no effect.
        self.assertEqual(self.probes["Memory-trust inheritance OFF"]["instruction_detector"], "ALLOW")

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
        # No imperative text in this probe; neither detector toggle has any effect.
        self.assertEqual(self.probes["Legacy pattern detector OFF"]["memory_trust"], "BLOCK")
        self.assertEqual(self.probes["Behavioral detector OFF"]["memory_trust"], "BLOCK")

    # ── Probe D: Safe-rewrite path ───────────────────────────────────────────
    # remediation_execute, 2 trusted sources. REWRITE regardless of any toggle.

    def test_probe_d_rewrite_in_all_configs(self) -> None:
        for label in ("Full policy (all ON)", "Corroboration backstop OFF",
                      "Legacy pattern detector OFF", "Memory-trust inheritance OFF",
                      "Behavioral detector OFF"):
            with self.subTest(config=label):
                self.assertEqual(self.probes[label]["rewrite"], "REWRITE")

    # ── Probe E: Tool-permission enforcement ─────────────────────────────────
    # Tool absent from allowed_tools. BLOCK regardless of any toggle.

    def test_probe_e_tool_block_in_all_configs(self) -> None:
        for label in ("Full policy (all ON)", "Corroboration backstop OFF",
                      "Legacy pattern detector OFF", "Memory-trust inheritance OFF",
                      "Behavioral detector OFF"):
            with self.subTest(config=label):
                self.assertEqual(self.probes[label]["tool_block"], "BLOCK")

    # ── Probe F: Behavioral detector vs. rephrased injection ─────────────────
    # run_remediation (criticality=0.85), rephrased text evades the legacy keyword scan in
    # every config; one trusted corroborating source keeps the corroboration backstop out of
    # play so pure risk-score math decides the outcome.
    # Behavioral ON: risk=0.845 -> BLOCK. Behavioral OFF: risk=0.495 -> ESCALATE.

    def test_probe_f_behavioral_on_blocks(self) -> None:
        for label in ("Full policy (all ON)", "Corroboration backstop OFF",
                      "Legacy pattern detector OFF", "Memory-trust inheritance OFF"):
            with self.subTest(config=label):
                self.assertEqual(self.probes[label]["behavioral_rephrase"], "BLOCK")

    def test_probe_f_behavioral_off_only_escalates(self) -> None:
        # The rephrased attack evades the legacy keyword scan entirely (0 contribution in
        # every config) -- without the behavioral signal, it only reaches ESCALATE, not BLOCK.
        self.assertEqual(self.probes["Behavioral detector OFF"]["behavioral_rephrase"], "ESCALATE")

