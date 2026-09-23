"""Data contracts shared by the SENTINEL defense components."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .behavioral_detector import BehavioralSignal


@dataclass(frozen=True)
class Observation:
    content: str
    source: str
    trust_label: str
    sensitivity: str


@dataclass(frozen=True)
class MemoryEntry:
    content: str
    trust_label: str
    derived_from: list[str]
    written_at: str


@dataclass(frozen=True)
class CandidateAction:
    action_type: str
    target: str
    justifying_observations: list[Observation] = field(default_factory=list)
    justifying_memory: list[MemoryEntry] = field(default_factory=list)
    params: dict = field(default_factory=dict)
    payload_sensitivity: float = 0.0
    intent_entities: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyContext:
    """Optional policy inputs supplied by an integration boundary."""

    allowed_tools: set[str] | None = None
    initial_intent_entities: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Decision:
    outcome: str
    risk_score: float
    reason_codes: list[str]
    explanation: str
    rewritten_action: CandidateAction | None = None
    behavioral_signal: "BehavioralSignal | None" = None
    payload_sensitivity: float = 0.0
    effective_criticality: float | None = None
    intent_drift_penalty: float = 0.0
    sensitivity_findings: list[str] = field(default_factory=list)
