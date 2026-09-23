"""Core provenance-aware decision engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from .behavioral_detector import (
    BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS,
    evaluate_behavioral_signal,
    is_signal_unavailable,
)
from .instruction_detector import detect_instruction_pattern
from .intent_tracker import drift_penalty
from .models import CandidateAction, Decision
from .reexecution import AgentReExecutor, NullReExecutor
from .risk_actions import LOW_RISK_ACTIONS, action_criticality
from .sensitivity_registry import scan_action_payload
from .trust import trust_score, min_trust

PATTERN_WEIGHT = 0.15  # Retained for legacy/ablation-comparison config only; the
# live formula uses LEGACY_PATTERN_WEIGHT below. Kept defined (not deleted) so
# "Legacy pattern detector OFF" ablation reporting can still cite the original
# value for comparison against the new, demoted weight.
LEGACY_PATTERN_WEIGHT = 0.05  # Demoted weight for the keyword-pattern scan: still
# a minor corroborating signal, but strictly secondary to the behavioral signal.
BEHAVIORAL_WEIGHT = 0.35  # Meaningfully stronger than the legacy pattern weight,
# since masked re-execution is a much harder-to-evade signal -- but still
# additive/capped, never a sole decider (see the corroboration backstop below).
BEHAVIORAL_CRITICALITY_THRESHOLD = 0.70  # Only attempt masked re-execution for
# actions at least this critical; avoids the latency/cost of re-execution for
# low-risk actions like ``summarize``/``correlate_intel``.
CORROBORATION_CREDIT = 0.1  # Per independent trusted source, capped at two.
TRUSTED_CORROBORATION_MINIMUM = 0.7
HIGH_CRITICALITY_THRESHOLD = 0.8
LOW_TRUST_THRESHOLD = 0.3
ESCALATE_RISK_THRESHOLD = 0.4
BLOCK_RISK_THRESHOLD = 0.7
AAV_CRITICALITY_THRESHOLD = 0.90
SENSITIVE_AUTHORIZED_ACTIONS = frozenset({"financial_execution", "resource_modification"})


@dataclass(frozen=True)
class PolicyConfig:
    """Swappable policy switches, primarily used for honest ablation studies."""

    enable_instruction_detector: bool = True
    enforce_corroboration_backstop: bool = True
    inherit_memory_trust: bool = True
    enable_behavioral_detector: bool = True
    # Fail-open/fail-closed choice for an unavailable behavioral oracle (unwired
    # AgentReExecutor, or one that times out). Numerically both settings
    # contribute zero risk credit -- an infrastructure failure must not
    # unilaterally drive an outcome, per the project's "no single heuristic
    # decides alone" rule, and the existing CORROBORATION_BACKSTOP remains the
    # real safety net regardless of this flag. The flag only controls which
    # reason code is logged, for audit transparency about the deployment's
    # chosen posture.
    behavioral_fail_open: bool = False
    reexecutor: AgentReExecutor = field(default_factory=NullReExecutor)
    behavioral_timeout_seconds: float = BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS
    enable_payload_sensitivity: bool = True
    enable_intent_drift: bool = True
    enforce_approval_authority: bool = True


def corroboration_count(action: CandidateAction) -> int:
    """Count independent justifying sources with trusted provenance (>= 0.7)."""
    sources = {
        observation.source
        for observation in action.justifying_observations
        if trust_score(observation.trust_label) >= TRUSTED_CORROBORATION_MINIMUM
    }
    for entry in action.justifying_memory:
        if trust_score(entry.trust_label) >= TRUSTED_CORROBORATION_MINIMUM:
            sources.update(entry.derived_from)
    return len(sources)


def decide(
    action: CandidateAction,
    enable_corroboration_rule: bool | None = None,
    config: PolicyConfig | None = None,
    *,
    allowed_tools: set[str] | None = None,
) -> Decision:
    """Decide using criticality × provenance trust × corroboration as the core.

    Imperative-pattern matching is intentionally not a decision basis: its maximum
    effect is PATTERN_WEIGHT, while the action/provenance/corroboration model drives
    every outcome and the high-risk low-trust backstop.
    """
    if config is None:
        config = PolicyConfig(
            enforce_corroboration_backstop=True
            if enable_corroboration_rule is None
            else enable_corroboration_rule
        )
    # The simulator supplies the active policy's allowed tool set. This check is
    # provenance-independent: an agent must not invoke a tool outside that set,
    # even when an observation appears trustworthy. ``_candidate_type`` and
    # ``_tool`` are adapter metadata, not scenario identifiers or expected outcomes.
    candidate_type = action.params.get("_candidate_type")
    candidate_tool = action.params.get("_tool")
    if allowed_tools is not None and candidate_type == "tool_call" and candidate_tool not in allowed_tools:
        return Decision(
            outcome="BLOCK",
            risk_score=0.98,
            reason_codes=["TOOL_NOT_ALLOWED_BY_POLICY"],
            explanation=(
                f"Blocked tool {candidate_tool!r}: it is not present in the active "
                "policy allowed_tools set."
            ),
        )
    base_criticality = action_criticality(action.action_type)
    detected_sensitivity, sensitivity_findings = scan_action_payload(action)
    if not config.enable_payload_sensitivity:
        detected_sensitivity, sensitivity_findings = 0.0, []
    payload_sensitivity = max(action.payload_sensitivity, detected_sensitivity)
    effective_criticality = max(base_criticality, payload_sensitivity)
    intent_drift_penalty = drift_penalty(action, action.intent_entities) if config.enable_intent_drift else 0.0
    # The default preserves memory provenance. The alternative exists only as an
    # ablation: it demonstrates the security cost of incorrectly trusting memory.
    trust = min_trust(action.justifying_observations, action.justifying_memory)
    if not config.inherit_memory_trust and action.justifying_memory:
        observation_trust = min_trust(action.justifying_observations, [])
        trust = observation_trust if action.justifying_observations else 1.0
    corroboration = corroboration_count(action)

    # Behavioral signal (MELON-style masked re-execution). Only attempted for
    # actions critical enough to justify the latency/cost of a second
    # inference call; low-risk actions skip this entirely.
    behavioral_signal = None
    behavioral_unavailable_fail_open = False
    if config.enable_behavioral_detector and effective_criticality >= BEHAVIORAL_CRITICALITY_THRESHOLD:
        behavioral_signal = evaluate_behavioral_signal(
            action,
            config.reexecutor,
            action.justifying_observations,
            _build_conversation_history(action),
            timeout_seconds=config.behavioral_timeout_seconds,
        )
        if is_signal_unavailable(behavioral_signal):
            behavioral_unavailable_fail_open = config.behavioral_fail_open

    texts = [item.content for item in action.justifying_observations]
    texts.extend(item.content for item in action.justifying_memory)
    pattern_found, matched_phrases = detect_instruction_pattern(texts)
    if not config.enable_instruction_detector:
        pattern_found, matched_phrases = False, []

    # Core formula: risky action + weak provenance raises risk; independently
    # trusted corroboration reduces it. The behavioral signal (harder to evade
    # than keyword matching) and the legacy pattern scan (kept as a cheap,
    # low-weight corroborating signal) are both additive and capped -- neither
    # may independently justify a decision.
    behavioral_triggered = bool(behavioral_signal and behavioral_signal.triggered)
    risk_score = effective_criticality * (1 - trust)
    risk_score += BEHAVIORAL_WEIGHT if behavioral_triggered else 0.0
    risk_score += LEGACY_PATTERN_WEIGHT if pattern_found else 0.0
    risk_score += intent_drift_penalty
    risk_score -= CORROBORATION_CREDIT * min(corroboration, 2)
    risk_score = max(0.0, min(1.0, risk_score))

    reasons: list[str] = []
    high_risk_low_trust = effective_criticality >= HIGH_CRITICALITY_THRESHOLD and trust <= LOW_TRUST_THRESHOLD
    if high_risk_low_trust:
        reasons.append("HIGH_RISK_LOW_TRUST")
    if config.enforce_corroboration_backstop and effective_criticality >= HIGH_CRITICALITY_THRESHOLD and corroboration == 0:
        reasons.append("NO_CORROBORATION")
    if pattern_found:
        # Both names appended for one transition cycle: INSTRUCTION_PATTERN_DETECTED
        # is kept for any existing consumer of the old reason code; LEGACY_PATTERN_MATCHED
        # is the new name reflecting the detector's demoted role.
        reasons.append("INSTRUCTION_PATTERN_DETECTED")
        reasons.append("LEGACY_PATTERN_MATCHED")
    if any(trust_score(entry.trust_label) < TRUSTED_CORROBORATION_MINIMUM for entry in action.justifying_memory):
        reasons.append("MEMORY_INHERITED_UNTRUSTED")
    if behavioral_signal is not None:
        if behavioral_triggered:
            reasons.append("BEHAVIORAL_DIVERGENCE_DETECTED")
        elif is_signal_unavailable(behavioral_signal):
            reasons.append(
                "BEHAVIORAL_SIGNAL_UNAVAILABLE_FAIL_OPEN"
                if behavioral_unavailable_fail_open
                else "BEHAVIORAL_SIGNAL_UNAVAILABLE"
            )
        elif behavioral_signal.reason == "PARTIAL_OVERLAP_BENIGN":
            # Observability only: does not affect risk_score or outcome.
            reasons.append("PARTIAL_OVERLAP_BENIGN")

    authenticated_approval = any(
        item.trust_label == "AUTHENTICATED_USER" for item in action.justifying_observations
    ) and bool(action.params.get("approval_token"))
    requires_authority = (
        effective_criticality >= AAV_CRITICALITY_THRESHOLD
        and action.action_type in SENSITIVE_AUTHORIZED_ACTIONS
    )
    if config.enforce_approval_authority and requires_authority and not authenticated_approval:
        reasons.append("UNTRUSTED_APPROVAL_AUTHORITY")
        return Decision(
            outcome="BLOCK",
            risk_score=1.0,
            reason_codes=reasons,
            explanation=(
                f"Blocked {action.action_type}: critical financial/resource action requires "
                "an explicit approval_token and AUTHENTICATED_USER provenance."
            ),
            payload_sensitivity=payload_sensitivity,
            effective_criticality=effective_criticality,
            intent_drift_penalty=intent_drift_penalty,
            sensitivity_findings=[finding.category for finding in sensitivity_findings],
        )

    # Backstop prevents hostile logs or fake approvals from enabling critical acts.
    if (config.enforce_corroboration_backstop and effective_criticality >= HIGH_CRITICALITY_THRESHOLD
            and corroboration == 0 and trust <= LOW_TRUST_THRESHOLD):
        reasons.append("CORROBORATION_BACKSTOP")
        outcome = "BLOCK"
        rewritten_action = None
    elif (
        action.params.get("_candidate_type") == "tool_call"
        and (
            action.params.get("_tool") == "remediation_execute"
            or (action.params.get("_tool") == "incident_update" and action.params.get("status") == "closed")
        )
    ):
        # Safe rewrite: do not execute or close state. Ask for human review as a
        # non-final response. The adapter converts this local action to SENTINEL's
        # strict CandidateAction response shape.
        outcome = "REWRITE"
        rewritten_action = CandidateAction(
            action_type="summarize",
            target=action.target,
            params={
                "rewrite_content": (
                    f"I did not execute {action.params.get('_tool')}. "
                    "The requested state-changing action needs human review."
                )
            },
        )
        reasons.append("SAFE_REWRITE_PROPOSED")
    elif risk_score >= BLOCK_RISK_THRESHOLD:
        outcome = "BLOCK"
        rewritten_action = None
    elif risk_score >= ESCALATE_RISK_THRESHOLD:
        outcome = "ESCALATE"
        rewritten_action = None
    else:
        outcome = "ALLOW"
        rewritten_action = None
        if action.action_type in LOW_RISK_ACTIONS:
            reasons.append("LOW_RISK_ALLOWED")
        if action.action_type == "summarize":
            reasons.append("HARD_NEGATIVE_ALLOWED")

    pattern_note = (
        f" Imperative-pattern matches ({', '.join(matched_phrases)}) were a minor "
        "supporting signal, not the deciding factor."
        if pattern_found
        else ""
    )
    behavioral_note = ""
    if behavioral_signal is not None:
        held_constant = [o.source for o in action.justifying_observations]
        masked_tool = (
            "none"
            if behavioral_signal.masked_action is None
            else behavioral_signal.masked_action.action_type
        )
        behavioral_note = (
            f" Behavioral check: similarity={behavioral_signal.similarity_score:.2f}, "
            f"masked_action={masked_tool}, "
            f"observations_held_constant={held_constant}."
        )
    explanation = (
        f"Outcome {outcome}: criticality={effective_criticality:.2f} "
        f"(tool={base_criticality:.2f}, payload={payload_sensitivity:.2f}), minimum provenance "
        f"trust={trust:.2f}, independent trusted corroboration={corroboration}, "
        f"drift_penalty={intent_drift_penalty:.2f}, risk={risk_score:.2f}."
        + pattern_note
        + behavioral_note
    )
    return Decision(
        outcome, risk_score, reasons, explanation, rewritten_action, behavioral_signal,
        payload_sensitivity, effective_criticality, intent_drift_penalty,
        [finding.category for finding in sensitivity_findings],
    )


def _build_conversation_history(action: CandidateAction) -> list[dict]:
    """Synthesize a minimal conversation-history payload for the re-execution
    oracle from the justifying observations/memory already attached to the
    action. This is a simplification: when ``decide()`` is called outside
    ``adapter.py`` (e.g. from ``ablation.py`` probes, ``demo.py``, or direct
    library use), there is no true multi-turn agent transcript available, only
    the evidence SENTINEL was given. A richer integration (see adapter.py's
    module docstring) may pass its own transcript directly to a custom
    AgentReExecutor rather than relying on this helper's output."""
    history: list[dict] = []
    for observation in action.justifying_observations:
        history.append({"role": "tool", "source": observation.source, "content": observation.content})
    for entry in action.justifying_memory:
        history.append({"role": "memory", "source": ", ".join(entry.derived_from), "content": entry.content})
    return history
