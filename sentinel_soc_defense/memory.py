"""Memory storage that preserves provenance trust across writes and reads."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import MemoryEntry, Observation
from .trust import TRUST_SCORES, trust_score


class MemoryStore:
    """In-memory implementation; this API can be backed by durable storage later."""

    def __init__(self) -> None:
        self._entries: list[MemoryEntry] = []

    def write(self, content: str, source_observations: list[Observation]) -> MemoryEntry:
        if not source_observations:
            raise ValueError("Memory writes require source observations for provenance")

        # Trust inheritance rule: memory can never be more trusted than its least
        # trusted source.  In particular, untrusted text cannot become policy by
        # being rewritten into the agent's own memory.
        lowest_source = min(source_observations, key=lambda item: trust_score(item.trust_label))
        entry = MemoryEntry(
            content=content,
            trust_label=lowest_source.trust_label
            if lowest_source.trust_label in TRUST_SCORES
            else "ADVERSARY_CONTROLLED",
            derived_from=[item.source for item in source_observations],
            written_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        return entry

    def read(self, query: str) -> list[MemoryEntry]:
        """Case-insensitive substring lookup without changing stored trust."""
        needle = query.lower()
        return [entry for entry in self._entries if needle in entry.content.lower()]
