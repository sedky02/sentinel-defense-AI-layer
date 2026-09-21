"""Data contracts shared by the SENTINEL defense components."""

from __future__ import annotations

from dataclasses import dataclass, field


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


@dataclass(frozen=True)
class Decision:
    outcome: str
    risk_score: float
    reason_codes: list[str]
    explanation: str
