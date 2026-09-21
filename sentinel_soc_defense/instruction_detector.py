"""This is a minor supporting signal only. It contributes a small weight to the risk score and must never independently justify a decision. Core decisions are driven by action criticality and provenance trust, per SENTINEL's rule against keyword-matching as a core defense."""

from __future__ import annotations

import re

# Small, replaceable heuristic for imperative language embedded in descriptive text.
_IMPERATIVE_PATTERNS = (
    r"\b(?:ignore|override|bypass)\b",
    r"\b(?:close|disable|suppress)\b.{0,40}\b(?:incident|monitoring|alert)\b",
    r"\b(?:run|execute)\b.{0,40}\b(?:command|remediation)\b",
)


def detect_instruction_pattern(texts: list[str]) -> tuple[bool, list[str]]:
    """Return matches only; policy assigns their strictly capped minor weight."""
    matches: list[str] = []
    for text in texts:
        for pattern in _IMPERATIVE_PATTERNS:
            found = re.search(pattern, text, flags=re.IGNORECASE)
            if found:
                matches.append(found.group(0))
    return bool(matches), matches
