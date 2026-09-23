"""Deterministic data-sensitivity fingerprints used by the policy boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SensitivityFinding:
    category: str
    sensitivity: float
    redacted_value: str


_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.95),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.90),
    ("secret_assignment", re.compile(r"\b(?:api[_ -]?key|secret|password|token)\s*[:=]\s*[^\s,;]{8,}", re.I), 0.90),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.I), 0.90),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), 0.90),
    ("internal_ip", re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), 0.70),
    ("email_address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), 0.70),
)


def _values(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [text for item in value.items() for text in _values(item)]
    if isinstance(value, (list, tuple, set)):
        return [text for item in value for text in _values(item)]
    return [str(value)] if value is not None else []


def scan_text(text: str) -> list[SensitivityFinding]:
    findings: list[SensitivityFinding] = []
    for category, pattern, sensitivity in _PATTERNS:
        for match in pattern.finditer(text):
            findings.append(SensitivityFinding(category, sensitivity, match.group(0)))
    return findings


def scan_action_payload(action: Any) -> tuple[float, list[SensitivityFinding]]:
    """Scan action arguments and evidence without interpreting instructions."""
    findings: list[SensitivityFinding] = []
    for value in _values(getattr(action, "params", {})):
        findings.extend(scan_text(value))
    for observation in getattr(action, "justifying_observations", []):
        findings.extend(scan_text(observation.content))
    for memory in getattr(action, "justifying_memory", []):
        findings.extend(scan_text(memory.content))
    unique: dict[tuple[str, str], SensitivityFinding] = {
        (finding.category, finding.redacted_value): finding for finding in findings
    }
    ordered = list(unique.values())
    return (max((finding.sensitivity for finding in ordered), default=0.0), ordered)


def redact_text(text: str) -> tuple[str, list[SensitivityFinding]]:
    """Replace detected values while preserving surrounding investigative context."""
    findings = scan_text(text)
    redacted = text
    for finding in sorted(findings, key=lambda item: len(item.redacted_value), reverse=True):
        redacted = redacted.replace(finding.redacted_value, "[REDACTED_BY_SENTINEL]")
    return redacted, findings