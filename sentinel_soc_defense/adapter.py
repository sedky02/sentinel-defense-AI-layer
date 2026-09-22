"""Exact HTTP contract adapter for SENTINEL Starter Kit v1.

Verified against ``starter-kits/python-defense`` at commit dd2e5fe.  The simulator
calls ``GET /healthz`` and ``POST /v1/decision``.  This module intentionally uses
only the standard library; its request/response shapes mirror the kit's Pydantic
models and are kept at this external-contract boundary.

Integrating a real AgentReExecutor
-----------------------------------
The masked-re-execution behavioral detector (``behavioral_detector.py``) needs an
``AgentReExecutor`` (see ``reexecution.py``) to ask "what would the agent propose
if its real task were masked out?". By default ``PolicyConfig.reexecutor`` is a
``NullReExecutor``, which raises loudly rather than silently skipping the check.
To wire up a real integration, implement the ``AgentReExecutor`` protocol against
your own agent runtime and pass an instance via ``PolicyConfig(reexecutor=...)``
(or, for this adapter's CLI, construct ``DefenseHandler.config`` directly rather
than through ``main()``'s flags, since a live re-execution integration is
deployment-specific). For example, replaying the same tool-call history through
a raw chat-completion call, substituting ``masked_task`` for the last user turn::

    class MyReExecutor:
        def __init__(self, client, model):
            self._client, self._model = client, model

        def propose_action_with_masked_task(self, original_observations,
                                              conversation_history, masked_task):
            messages = [{"role": "system", "content": masked_task}]
            messages += [{"role": h.get("role", "tool"), "content": h["content"]}
                         for h in conversation_history]
            response = self._client.chat.completions.create(
                model=self._model, messages=messages, tools=[...])
            # Parse the proposed tool call into a CandidateAction here, WITHOUT
            # ever dispatching it to the real tool executor -- this call must
            # only observe what the agent *would* propose, never execute it.
            return _candidate_action_from_tool_call(response)

A LangGraph node or any other agent runtime can implement the same protocol:
the only requirement is that it observes a proposed action without executing it.
"""

from __future__ import annotations

import argparse
import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .behavioral_detector import BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS
from .extraction import DEFAULT_SCHEMA_REGISTRY, ExtractedFact, extract_facts
from .models import CandidateAction, MemoryEntry, Observation
from .policy import HIGH_CRITICALITY_THRESHOLD, PolicyConfig, decide
from .risk_actions import action_criticality
from .trace import TraceLogger
from .trust import inherit_trust_label

_logger = logging.getLogger("sentinel.adapter")
_logger.addHandler(logging.NullHandler())

TRUST_LABELS = {
    "system_policy": "SYSTEM_POLICY", "authenticated_user": "AUTHENTICATED_USER",
    "trusted_internal": "TRUSTED_INTERNAL", "untrusted_internal": "UNTRUSTED_INTERNAL",
    "untrusted_external": "UNTRUSTED_EXTERNAL", "adversary_controlled": "ADVERSARY_CONTROLLED",
}

# Maps a substring of the wire-level provenance ``source_id`` to an extraction.py
# source_type. Unmatched source_ids resolve to None (a schema-registry miss --
# extract nothing) rather than guessing at a schema. A provenance entry can also
# declare its own ``source_type``/``kind`` directly (checked first, for forward
# compatibility with a simulator that starts sending it).
SOURCE_TYPE_MAP: dict[str, str] = {
    "web-server": "web_server_log", "web_server": "web_server_log", "http": "web_server_log",
    "email": "email", "inbox": "email", "mail": "email",
    "ticket": "ticket", "helpdesk": "ticket", "case-system": "ticket",
    "chat": "analyst_chat", "analyst": "analyst_chat", "soc-lead": "analyst_chat",
    "edr": "edr_siem_alert", "siem": "edr_siem_alert", "alert": "edr_siem_alert",
}


def _resolve_source_type(provenance_entry: dict[str, Any], source_id: str) -> str | None:
    declared = provenance_entry.get("source_type") or provenance_entry.get("kind")
    if isinstance(declared, str) and declared in DEFAULT_SCHEMA_REGISTRY:
        return declared
    lowered = source_id.lower()
    for fragment, source_type in SOURCE_TYPE_MAP.items():
        if fragment in lowered:
            return source_type
    return None


def _fact_to_dict(fact: ExtractedFact) -> dict[str, Any]:
    return {
        "field": fact.field, "value": fact.value,
        "source_observation_id": fact.source_observation_id,
        "trust_label": fact.trust_label, "extraction_confidence": fact.extraction_confidence,
    }


def _revalidate_extracted_facts(
    claimed_facts: list[Any],
    observation_by_source: dict[str, Observation],
    source_type_by_source: dict[str, str | None],
) -> list[dict[str, Any]]:
    """Never trust a caller's claim that extraction already happened correctly:
    re-check every ``extraction_mode="pre_extracted"`` fact against the same
    schema allowlist ``extraction_mode="raw"`` would have used, and rebuild
    ``trust_label`` from the actual observation rather than the caller's claim
    -- the same belt-and-suspenders pattern ``decide()`` already uses by
    re-deriving trust/criticality instead of trusting caller-supplied risk
    fields. A fact that fails any check is dropped, not passed through."""
    validated: list[dict[str, Any]] = []
    for raw in claimed_facts:
        if not isinstance(raw, dict):
            continue
        source_id = raw.get("source_observation_id")
        field_name = raw.get("field")
        observation = observation_by_source.get(source_id)
        source_type = source_type_by_source.get(source_id)
        if observation is None or source_type is None:
            continue
        schema = DEFAULT_SCHEMA_REGISTRY.get(source_type)
        if schema is None or field_name not in schema.allowed_fields:
            continue
        value = str(raw.get("value", "")).strip()
        if not value:
            continue
        try:
            confidence = float(raw.get("extraction_confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        validated.append({
            "field": field_name, "value": value, "source_observation_id": source_id,
            "trust_label": inherit_trust_label([observation]),
            "extraction_confidence": confidence,
        })
    return validated


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


def translate_request(payload: dict[str, Any], *, extraction_mode: str = "raw") -> CandidateAction:
    """Translate SENTINEL's v1 ``DefenseRequest`` into local policy models.

    The official request provides provenance IDs rather than pre-attached action
    justifications. We use every provenance-bearing observation/conversation item
    that the agent has seen; untrusted memory remains represented as memory.

    ``extraction_mode`` controls how untrusted observation text reaches the rest
    of the pipeline (see ``extraction.py``):

    - ``"raw"`` (the default, for backward compatibility with every existing
      caller): every observation is run through ``extract_facts()`` here, and
      the resulting schema-validated facts are attached as
      ``CandidateAction.params["_extracted_facts"]``. This keeps the safety
      property intact even for integrators who never send ``extracted_facts``.
    - ``"pre_extracted"``: ``payload["extracted_facts"]`` is used, but always
      re-validated against the same schema allowlist rather than trusted as-is
      (see ``_revalidate_extracted_facts``).
    """
    provenance_entries = {item.get("id"): item for item in payload.get("provenance", [])}
    provenance = {item_id: entry.get("provenance", {}) for item_id, entry in provenance_entries.items()}
    observations: list[Observation] = []
    memory: list[MemoryEntry] = []
    extracted_fact_dicts: list[dict[str, Any]] = []
    observation_by_source: dict[str, Observation] = {}
    source_type_by_source: dict[str, str | None] = {}
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
            source_id = str(lowest.get("source_id", ids[0]))
            observation = Observation(content, source_id, label, str(lowest.get("sensitivity", "internal")).upper())
            observations.append(observation)
            observation_by_source[source_id] = observation
            source_type = _resolve_source_type(lowest, source_id)
            source_type_by_source[source_id] = source_type
            if extraction_mode == "raw" and source_type is not None:
                facts, _dropped = extract_facts(observation, source_type, DEFAULT_SCHEMA_REGISTRY)
                extracted_fact_dicts.extend(_fact_to_dict(fact) for fact in facts)
    candidate = payload["candidate_action"]
    # Confirmation requests guard the action being confirmed, as in the official kit.
    guarded = candidate.get("confirmation_for") if candidate.get("type") == "request_confirmation" else candidate
    guarded = guarded or candidate
    arguments = dict(guarded.get("arguments", {}))
    target = str(guarded.get("tool", guarded.get("content", "agent_response")))
    arguments["_candidate_type"] = str(guarded.get("type", ""))
    arguments["_tool"] = guarded.get("tool")
    if extraction_mode == "pre_extracted":
        extracted_fact_dicts = _revalidate_extracted_facts(
            payload.get("extracted_facts", []), observation_by_source, source_type_by_source,
        )
    arguments["_extracted_facts"] = extracted_fact_dicts
    return CandidateAction(_action_type(guarded), target, observations, memory, arguments)


def decision_response(payload: dict[str, Any], config: PolicyConfig | None = None) -> tuple[CandidateAction, Any, dict[str, Any]]:
    extraction_mode = payload.get("extraction_mode", "raw")
    action = translate_request(payload, extraction_mode=extraction_mode)
    policy_context = payload.get("policy_context", {})
    configured_tools = policy_context.get("allowed_tools")
    allowed_tools = set(configured_tools) if isinstance(configured_tools, list) else None
    result = decide(action, config=config, allowed_tools=allowed_tools)
    if extraction_mode == "raw" and action_criticality(action.action_type) >= HIGH_CRITICALITY_THRESHOLD:
        _logger.warning(
            "extraction_mode='raw' used for a high-criticality action (%s); consider "
            "migrating this integration to extraction_mode='pre_extracted'.",
            action.action_type,
        )
    # Exact ``DefenseDecision`` shape: lower-case enum, risk/confidence, bounded metadata.
    rewritten = None
    if result.rewritten_action is not None:
        rewritten = {
            "type": "respond", "tool": None, "arguments": {},
            "content": str(result.rewritten_action.params.get("rewrite_content", "Human review required.")),
            "final": False, "confirmation_for": None,
        }
    behavioral_signal = None
    if result.behavioral_signal is not None:
        behavioral_signal = {
            "triggered": result.behavioral_signal.triggered,
            "similarity_score": result.behavioral_signal.similarity_score,
            "reason": result.behavioral_signal.reason,
        }
    response = {"decision": result.outcome.lower(), "risk_score": result.risk_score,
                "confidence": round(max(0.1, 1.0 - abs(result.risk_score - 0.5)), 2),
                "reason_codes": result.reason_codes[:16], "explanation": result.explanation[:500],
                "rewritten_action": rewritten,
                "metadata": {"action_criticality_input": action.action_type,
                             "observation_count": len(action.justifying_observations),
                             "memory_count": len(action.justifying_memory),
                             "behavioral_signal": behavioral_signal}}
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
    parser.add_argument("--disable-behavioral-detector", action="store_true")
    parser.add_argument("--behavioral-fail-open", action="store_true")
    parser.add_argument("--behavioral-timeout-seconds", type=float, default=BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS)
    args = parser.parse_args(); DefenseHandler.logger = TraceLogger(Path(args.trace)); DefenseHandler.config = PolicyConfig(
        enable_instruction_detector=not args.disable_pattern,
        enforce_corroboration_backstop=not args.disable_corroboration_backstop,
        inherit_memory_trust=not args.disable_memory_inheritance,
        enable_behavioral_detector=not args.disable_behavioral_detector,
        behavioral_fail_open=args.behavioral_fail_open,
        behavioral_timeout_seconds=args.behavioral_timeout_seconds,
    )
    print(f"SENTINEL v1 adapter listening on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), DefenseHandler).serve_forever()


if __name__ == "__main__": main()
