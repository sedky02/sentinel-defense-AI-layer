"""Small deterministic entity tracker for authenticated-task drift checks."""

from __future__ import annotations

import re
from collections.abc import Iterable

DRIFT_PENALTY = 0.30
OUTBOUND_ACTIONS = frozenset({
    "send_email", "send_message", "send_money", "financial_execution",
    "resource_modification", "exfiltrate", "upload_data",
})
_ENTITY_PATTERN = re.compile(
    r"(?:[A-Z][A-Za-z0-9_-]{2,}|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|"
    r"https?://[^\s)]+|\b(?:\d{1,3}\.){3}\d{1,3}\b)",
)


def extract_entities(text: str) -> set[str]:
    return {match.group(0).rstrip(".,;:)").lower() for match in _ENTITY_PATTERN.finditer(text)}


def extract_authenticated_intent(observations: Iterable[object]) -> list[str]:
    entities: set[str] = set()
    for observation in observations:
        if getattr(observation, "trust_label", "") == "AUTHENTICATED_USER":
            entities.update(extract_entities(getattr(observation, "content", "")))
    return sorted(entities)


def action_entities(action: object) -> set[str]:
    entities = extract_entities(str(getattr(action, "target", "")))
    params = getattr(action, "params", {})
    for key, value in params.items():
        if not str(key).startswith("_"):
            entities.update(extract_entities(str(value)))
    return entities


def drift_penalty(action: object, initial_entities: Iterable[str]) -> float:
    if getattr(action, "action_type", "") not in OUTBOUND_ACTIONS:
        return 0.0
    initial = {entity.lower() for entity in initial_entities}
    current = action_entities(action)
    return DRIFT_PENALTY if initial and current and initial.isdisjoint(current) else 0.0