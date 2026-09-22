"""Optional AgentDojo bridge for evaluating SENTINEL as a tool-call gate.

AgentDojo is intentionally an optional dependency. This module keeps the
benchmark integration outside the normal adapter and policy paths, while using
the same ``decide`` function for every proposed tool call.
"""

from __future__ import annotations

from ast import literal_eval
from pathlib import Path
from typing import Any

from .models import CandidateAction, Decision, Observation
from .policy import decide
from .trace import TraceLogger


READ_ACTION_NAMES = {
    "get", "list", "read", "search", "lookup", "fetch", "find", "query",
    "view", "check", "retrieve", "describe", "history", "status",
}


def action_type_for_tool(tool_name: str) -> str:
    """Map an AgentDojo tool name to SENTINEL's scenario-agnostic registry."""
    normalized = tool_name.lower()
    if any(word in normalized for word in ("send", "delete", "remove", "transfer", "pay", "write", "update", "create", "move", "cancel", "book")):
        return "run_remediation"
    if any(word in normalized for word in READ_ACTION_NAMES):
        return "summarize"
    return "summarize"


def observations_from_messages(messages: list[dict[str, Any]]) -> list[Observation]:
    """Convert prior user/tool messages into conservative provenance evidence."""
    observations: list[Observation] = []
    for index, message in enumerate(messages):
        role = message.get("role")
        content = _content_as_text(message.get("content"))
        if not content:
            continue
        if role == "user":
            label, source = "AUTHENTICATED_USER", "agentdojo-user"
        elif role == "tool":
            # Tool output is data, not an instruction authority. Treating it as
            # adversary-controlled is conservative and matches this benchmark's
            # indirect-injection threat model.
            label, source = "ADVERSARY_CONTROLLED", "agentdojo-tool"
        else:
            continue
        observations.append(Observation(content, f"{source}-{index}", label, "internal"))
    return observations


def evaluate_tool_call(tool_name: str, args: dict[str, Any], messages: list[dict[str, Any]]) -> tuple[CandidateAction, Decision]:
    """Evaluate one AgentDojo function call using the existing policy engine."""
    action = CandidateAction(
        action_type_for_tool(tool_name),
        tool_name,
        justifying_observations=observations_from_messages(messages),
        params={"_candidate_type": "tool_call", "_tool": tool_name, **args},
    )
    return action, decide(action, allowed_tools={tool_name})


def make_tools_executor(trace_path: str | Path | None = None) -> Any:
    """Create a current AgentDojo ``ToolsExecutor`` with a SENTINEL gate.

    Imports are local because AgentDojo is optional and its public API is still
    evolving. The returned object is suitable for ``ToolsExecutionLoop``.
    """
    try:
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list, tool_result_to_str
        from agentdojo.functions_runtime import EmptyEnv
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
    except ImportError as error:  # pragma: no cover - exercised only without optional dependency
        raise RuntimeError("AgentDojo is not installed. Install it with: pip install agentdojo") from error

    class SentinelToolsExecutor(ToolsExecutor):
        def __init__(self) -> None:
            super().__init__()
            self.sentinel_logger = TraceLogger(trace_path) if trace_path else None

        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
            if not messages or messages[-1].get("role") != "assistant":
                return query, runtime, env, messages, extra_args or {}
            calls = messages[-1].get("tool_calls") or []
            if not calls:
                return query, runtime, env, messages, extra_args or {}

            prior_messages = list(messages[:-1])
            results = []
            for call in calls:
                args = dict(call.args)
                action, decision = evaluate_tool_call(call.function, args, prior_messages)
                if self.sentinel_logger:
                    self.sentinel_logger.log(
                        action,
                        decision,
                        session_id="agentdojo",
                        metadata={"benchmark": "AgentDojo", "tool": call.function},
                    )
                if decision.outcome != "ALLOW":
                    message = (
                        f"SENTINEL {decision.outcome}: tool execution was not performed. "
                        f"{decision.explanation} Human approval is required."
                    )
                    results.append(ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(message)],
                        tool_call_id=call.id,
                        tool_call=call,
                        error=message,
                    ))
                    continue

                if call.function not in (tool.name for tool in runtime.functions.values()):
                    results.append(ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=call.id,
                        tool_call=call,
                        error=f"Invalid tool {call.function} provided.",
                    ))
                    continue
                for arg_name, arg_value in args.items():
                    if isinstance(arg_value, str) and is_string_list(arg_value):
                        args[arg_name] = literal_eval(arg_value)
                value, error = runtime.run_function(env, call.function, args)
                results.append(ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(tool_result_to_str(value))],
                    tool_call_id=call.id,
                    tool_call=call,
                    error=error,
                ))
            return query, runtime, env, [*messages, *results], extra_args or {}

    return SentinelToolsExecutor()


def _content_as_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(block.get("content", "")) for block in content if isinstance(block, dict))
    return "" if content is None else str(content)
