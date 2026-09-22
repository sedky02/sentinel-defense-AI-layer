"""Core provenance-aware decision engine."""

from __future__ import annotations

from dataclasses import dataclass

from .instruction_detector import detect_instruction_pattern
from .models import CandidateAction, Decision
from .risk_actions import LOW_RISK_ACTIONS, action_criticality
from .trust import trust_score, min_trust

PATTERN_WEIGHT = 0.15  # Strict maximum: detector can only be a minor signal.
CORROBORATION_CREDIT = 0.1  # Per independent trusted source, capped at two.
TRUSTED_CORROBORATION_MINIMUM = 0.7
HIGH_CRITICALITY_THRESHOLD = 0.8
LOW_TRUST_THRESHOLD = 0.3
ESCALATE_RISK_THRESHOLD = 0.4
BLOCK_RISK_THRESHOLD = 0.7


@dataclass(frozen=True)
class PolicyConfig:
    """Swappable policy switches, primarily used for honest ablation studies."""

    enable_instruction_detector: bool = True
    enforce_corroboration_backstop: bool = True
    inherit_memory_trust: bool = True


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
    criticality = action_criticality(action.action_type)
    # The default preserves memory provenance. The alternative exists only as an
    # ablation: it demonstrates the security cost of incorrectly trusting memory.
    trust = min_trust(action.justifying_observations, action.justifying_memory)
    if not config.inherit_memory_trust and action.justifying_memory:
        observation_trust = min_trust(action.justifying_observations, [])
        trust = observation_trust if action.justifying_observations else 1.0
    corroboration = corroboration_count(action)
    texts = [item.content for item in action.justifying_observations]
    texts.extend(item.content for item in action.justifying_memory)
    pattern_found, matched_phrases = detect_instruction_pattern(texts)
    if not config.enable_instruction_detector:
        pattern_found, matched_phrases = False, []

    # Core formula: risky action + weak provenance raises risk; independently
    # trusted corroboration reduces it. Pattern matching is capped at 0.15.
    risk_score = criticality * (1 - trust)
    risk_score += PATTERN_WEIGHT if pattern_found else 0.0
    risk_score -= CORROBORATION_CREDIT * min(corroboration, 2)
    risk_score = max(0.0, min(1.0, risk_score))

    reasons: list[str] = []
    high_risk_low_trust = criticality >= HIGH_CRITICALITY_THRESHOLD and trust <= LOW_TRUST_THRESHOLD
    if high_risk_low_trust:
        reasons.append("HIGH_RISK_LOW_TRUST")
    if config.enforce_corroboration_backstop and criticality >= HIGH_CRITICALITY_THRESHOLD and corroboration == 0:
        reasons.append("NO_CORROBORATION")
    if pattern_found:
        reasons.append("INSTRUCTION_PATTERN_DETECTED")
    if any(trust_score(entry.trust_label) < TRUSTED_CORROBORATION_MINIMUM for entry in action.justifying_memory):
        reasons.append("MEMORY_INHERITED_UNTRUSTED")

    # Backstop prevents hostile logs or fake approvals from enabling critical acts.
    if (config.enforce_corroboration_backstop and criticality >= HIGH_CRITICALITY_THRESHOLD
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
    explanation = (
        f"Outcome {outcome}: criticality={criticality:.2f}, minimum provenance "
        f"trust={trust:.2f}, independent trusted corroboration={corroboration}, "
        f"risk={risk_score:.2f}."
        + pattern_note
    )
    return Decision(outcome, risk_score, reasons, explanation, rewritten_action)
