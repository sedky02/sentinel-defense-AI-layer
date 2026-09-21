"""Trust labels and provenance-aware trust aggregation."""

from collections.abc import Iterable

from .models import MemoryEntry, Observation

# Scores describe provenance reliability, not how alarming the text sounds.
TRUST_SCORES: dict[str, float] = {
    "SYSTEM_POLICY": 1.0,
    "AUTHENTICATED_USER": 0.85,
    "TRUSTED_INTERNAL": 0.7,
    "UNTRUSTED_INTERNAL": 0.3,
    "UNTRUSTED_EXTERNAL": 0.2,
    "ADVERSARY_CONTROLLED": 0.0,
}


def trust_score(trust_label: str) -> float:
    """Return a conservative score; unknown labels are untrusted."""
    return TRUST_SCORES.get(trust_label, 0.0)


def min_trust(
    observations: Iterable[Observation], memory_entries: Iterable[MemoryEntry]
) -> float:
    """Return the weakest provenance score among all action justifications.

    Memory uses its inherited label exactly: agent-written text receives no trust
    upgrade merely because it was read from memory.
    """
    scores = [trust_score(item.trust_label) for item in observations]
    scores.extend(trust_score(item.trust_label) for item in memory_entries)
    return min(scores) if scores else 0.0
