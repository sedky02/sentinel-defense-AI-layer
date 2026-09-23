"""Downstream tool-output redaction before untrusted data reaches agent context."""

from __future__ import annotations

from typing import Any

from .sensitivity_registry import SensitivityFinding, redact_text


def filter_response(content: str) -> tuple[str, list[SensitivityFinding]]:
    """Return a context-safe response while preserving non-sensitive text."""
    return redact_text(content)


def filter_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Filter the common response shapes without trusting caller metadata."""
    if isinstance(payload.get("content"), str):
        content, findings = filter_response(payload["content"])
        return {
            "content": content,
            "redacted": bool(findings),
            "findings": [finding.category for finding in findings],
        }
    observation = payload.get("observation")
    if isinstance(observation, dict) and isinstance(observation.get("content"), str):
        content, findings = filter_response(observation["content"])
        filtered = dict(observation)
        filtered["content"] = content
        return {
            "observation": filtered,
            "redacted": bool(findings),
            "findings": [finding.category for finding in findings],
        }
    raise ValueError("response_filter requires a string content or observation.content")
