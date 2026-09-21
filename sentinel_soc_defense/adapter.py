"""Exact HTTP contract adapter for SENTINEL Starter Kit v1.

Verified against ``starter-kits/python-defense`` at commit dd2e5fe.  The simulator
calls ``GET /healthz`` and ``POST /v1/decision``.  This module intentionally uses
only the standard library; its request/response shapes mirror the kit's Pydantic
models and are kept at this external-contract boundary.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .models import CandidateAction, MemoryEntry, Observation
from .policy import PolicyConfig, decide
from .trace import TraceLogger

TRUST_LABELS = {
    "system_policy": "SYSTEM_POLICY", "authenticated_user": "AUTHENTICATED_USER",
    "trusted_internal": "TRUSTED_INTERNAL", "untrusted_internal": "UNTRUSTED_INTERNAL",
    "untrusted_external": "UNTRUSTED_EXTERNAL", "adversary_controlled": "ADVERSARY_CONTROLLED",
}


def _label(value: str) -> str:
    return TRUST_LABELS.get(value.lower(), "ADVERSARY_CONTROLLED")


def _action_type(candidate: dict[str, Any]) -> str:
    """Map official SOC tool semantics to our scenario-agnostic action registry."""
    if candidate.get("type") != "tool_call":
        return "summarize" if candidate.get("type") == "respond" else "add_comment"
    tool, args = str(candidate.get("tool", "unknown")), candidate.get("arguments", {})
    if tool == "incident_update":
        return "close_incident" if args.get("status") == "closed" else "add_comment"
    if tool == "remediation_prepare":
        return "disable_monitoring" if args.get("action") == "disable_monitoring" else "run_remediation"
    if tool == "remediation_execute": return "run_remediation"
    if tool == "intel_search": return "correlate_intel"
    if tool in {"alert_search", "alert_read", "asset_lookup"}: return "summarize"
    return tool


def translate_request(payload: dict[str, Any]) -> CandidateAction:
    """Translate SENTINEL's v1 ``DefenseRequest`` into local policy models.

    The official request provides provenance IDs rather than pre-attached action
    justifications. We use every provenance-bearing observation/conversation item
    that the agent has seen; untrusted memory remains represented as memory.
    """
    provenance = {item.get("id"): item.get("provenance", {}) for item in payload.get("provenance", [])}
    observations: list[Observation] = []
    memory: list[MemoryEntry] = []
    items: list[dict[str, Any]] = list(payload.get("conversation", []))
    if payload.get("observation"): items.append(payload["observation"])
    for item in items:
        ids = list(item.get("provenance_ids", []))
        if not ids: continue
        sources = [provenance.get(item_id, {}) for item_id in ids]
        lowest = min(sources, key=lambda p: list(TRUST_LABELS).index(p.get("trust_level", "adversary_controlled")) if p.get("trust_level") in TRUST_LABELS else 5)
        content = str(item.get("content", ""))
        label = _label(str(lowest.get("trust_level", "adversary_controlled")))
        if item.get("kind") == "memory":
            memory.append(MemoryEntry(content, label, ids, "simulator-history"))
        else:
            observations.append(Observation(content, str(lowest.get("source_id", ids[0])), label, str(lowest.get("sensitivity", "internal")).upper()))
    candidate = payload["candidate_action"]
    # Confirmation requests guard the action being confirmed, as in the official kit.
    guarded = candidate.get("confirmation_for") if candidate.get("type") == "request_confirmation" else candidate
    guarded = guarded or candidate
    arguments = dict(guarded.get("arguments", {}))
    target = str(guarded.get("tool", guarded.get("content", "agent_response")))
    return CandidateAction(_action_type(guarded), target, observations, memory, arguments)


def decision_response(payload: dict[str, Any], config: PolicyConfig | None = None) -> tuple[CandidateAction, Any, dict[str, Any]]:
    action = translate_request(payload)
    result = decide(action, config=config)
    # Exact ``DefenseDecision`` shape: lower-case enum, risk/confidence, bounded metadata.
    response = {"decision": result.outcome.lower(), "risk_score": result.risk_score,
                "confidence": round(max(0.1, 1.0 - abs(result.risk_score - 0.5)), 2),
                "reason_codes": result.reason_codes[:16], "explanation": result.explanation[:500],
                "metadata": {"action_criticality_input": action.action_type,
                             "observation_count": len(action.justifying_observations),
                             "memory_count": len(action.justifying_memory)}}
    return action, result, response


class DefenseHandler(BaseHTTPRequestHandler):
    logger = TraceLogger(); config = PolicyConfig()

    def _json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        encoded = json.dumps(body).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/healthz": self._json(HTTPStatus.OK, {"status": "ok"})
        else: self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/v1/decision": self.send_error(HTTPStatus.NOT_FOUND); return
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            action, result, response = decision_response(payload, self.config)
            self.logger.log(action, result, session_id=str(payload.get("run_id", "simulator")), metadata={
                "step_id": payload.get("step_id"), "history_digest": payload.get("history_digest", {}),
                "simulator_request": payload, "simulator_response": response})
            self._json(HTTPStatus.OK, response)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)[:500]})

    def log_message(self, format: str, *args: object) -> None: return


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8080); parser.add_argument("--trace", default="sentinel_decisions.jsonl"); parser.add_argument("--disable-pattern", action="store_true"); parser.add_argument("--disable-corroboration-backstop", action="store_true"); parser.add_argument("--disable-memory-inheritance", action="store_true")
    args = parser.parse_args(); DefenseHandler.logger = TraceLogger(Path(args.trace)); DefenseHandler.config = PolicyConfig(not args.disable_pattern, not args.disable_corroboration_backstop, not args.disable_memory_inheritance)
    print(f"SENTINEL v1 adapter listening on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), DefenseHandler).serve_forever()


if __name__ == "__main__": main()
