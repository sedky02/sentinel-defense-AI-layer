"""Pluggable interface for masked re-execution (MELON-style) behavioral detection.

Rationale: SENTINEL cannot itself run an agent's reasoning loop -- it is a passive
policy evaluator sitting between the agent and its tools. To detect data-driven
(prompt-injected) actions rather than task-driven ones, SENTINEL needs to ask a
re-execution oracle: "what would the agent propose if the user's real task were
masked out, holding observations/tool outputs constant?" If the same action
reappears under a neutral, no-op task, that is strong evidence the action is
driven by content in the observations, not by the user's actual intent. See
"MELON: Provable Indirect Prompt Injection Defense via Masked Re-execution and
Tool Comparison" (arXiv:2502.05174).

Integrators wire a real AgentReExecutor implementation (a LangGraph node, a raw
chat-completion replay, etc.) -- see adapter.py's module docstring for a worked
example. If none is wired up, NullReExecutor is used by default and fails loudly
(raises NotConfiguredError) rather than silently degrading the behavioral check.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .models import CandidateAction, Observation


class NotConfiguredError(RuntimeError):
    """Raised by NullReExecutor: makes an unwired behavioral detector loud, not silent."""


class AgentReExecutor(Protocol):
    """Implemented by whoever integrates SENTINEL with their agent runtime."""

    def propose_action_with_masked_task(
        self,
        original_observations: list[Observation],
        conversation_history: list[dict],
        masked_task: str,
    ) -> Optional[CandidateAction]:
        """Given the same observations/tool-call history but a masked (neutral)
        user task, return the action the agent would propose, or None if the
        agent proposes no action. Must NOT actually execute the action."""
        ...


@dataclass(frozen=True)
class NullReExecutor:
    """Default no-op executor. Always raises NotConfiguredError so a deployment
    that never wired up a real re-execution integration fails loudly instead of
    silently skipping the behavioral check."""

    def propose_action_with_masked_task(
        self,
        original_observations: list[Observation],
        conversation_history: list[dict],
        masked_task: str,
    ) -> Optional[CandidateAction]:
        raise NotConfiguredError(
            "No AgentReExecutor configured. Behavioral detection cannot run. "
            "Wire a real implementation into PolicyConfig.reexecutor (see "
            "adapter.py's module docstring, 'Integrating a real AgentReExecutor') "
            "or accept the documented fail-open/fail-closed default via "
            "PolicyConfig.behavioral_fail_open."
        )


@dataclass(frozen=True)
class MockReExecutor:
    """Test/ablation double. Returns a fixed CandidateAction (or None) per
    scenario_key, driven by fixture data, so the behavioral detector's logic
    can be fully unit-tested without a live LLM call. latency_seconds lets
    tests simulate a slow re-execution call for timeout testing."""

    fixture: dict[str, Optional[CandidateAction]] = field(default_factory=dict)
    scenario_key: str = ""
    latency_seconds: float = 0.0

    def propose_action_with_masked_task(
        self,
        original_observations: list[Observation],
        conversation_history: list[dict],
        masked_task: str,
    ) -> Optional[CandidateAction]:
        if self.latency_seconds:
            time.sleep(self.latency_seconds)
        return self.fixture.get(self.scenario_key)
