"""Structural (non-LLM-judged) comparison between an agent's originally proposed
CandidateAction and the action it proposes when re-executed with a masked
(neutral) task, per MELON (arXiv:2502.05174). Determinism is required: this
module must always return the same BehavioralSignal for the same inputs, so it
can be unit tested and relied upon as a policy input rather than a fuzzy judge.

This is a *signal computer only*. It does not decide fail-open vs fail-closed
policy for an unavailable oracle -- it normalizes any NotConfiguredError/timeout
into a BehavioralSignal whose `reason` is prefixed with
"BEHAVIORAL_SIGNAL_UNAVAILABLE", and leaves policy.py as the sole place that
interprets that prefix according to the deployment's configured choice.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass
from typing import Optional

from .masking import mask_task
from .models import CandidateAction, Observation
from .reexecution import AgentReExecutor, NotConfiguredError

CRITICAL_ARG_KEYS: tuple[str, ...] = ("host_id", "incident_id", "asset_id", "alert_id")
"""Params keys treated as the 'primary target/critical argument' for a strong
similarity match, in addition to CandidateAction.target itself."""

BEHAVIORAL_TRIGGER_THRESHOLD: float = 1.0
"""Only an exact tool+target match (similarity_score == 1.0) triggers the
behavioral signal. Partial overlap (same tool, different target) is logged for
observability but must never independently count as an attack signal."""

BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS: float = 3.0
"""Default wall-clock budget for a single masked re-execution call."""

_UNAVAILABLE_PREFIX = "BEHAVIORAL_SIGNAL_UNAVAILABLE"


@dataclass(frozen=True)
class BehavioralSignal:
    triggered: bool
    similarity_score: float  # 0.0 (completely different actions) to 1.0 (identical)
    masked_action: Optional[CandidateAction]
    reason: str
    latency_seconds: float = 0.0


def _critical_args_match(original: CandidateAction, masked: CandidateAction) -> bool:
    """True if target matches, or any shared CRITICAL_ARG_KEYS value matches."""
    if original.target == masked.target:
        return True
    for key in CRITICAL_ARG_KEYS:
        if key in original.params and key in masked.params and original.params[key] == masked.params[key]:
            return True
    return False


def _score_similarity(
    original: CandidateAction, masked: Optional[CandidateAction]
) -> tuple[float, str]:
    """Implements the four-case scoring contract:

    1. No masked action proposed -- the agent correctly did nothing when given
       a neutral task. This is the expected, healthy case.
    2. Same action_type AND same target/critical argument -- strong signal that
       the action is data-driven, not task-driven.
    3. Same action_type, different target/critical argument -- weak/no signal;
       logged as PARTIAL_OVERLAP_BENIGN for observability, never treated as an
       attack.
    4. Different action_type entirely -- no signal.
    """
    if masked is None:
        return 0.0, "NO_MASKED_ACTION_PROPOSED"
    if original.action_type == masked.action_type:
        if _critical_args_match(original, masked):
            return 1.0, "SAME_TOOL_SAME_TARGET"
        return 0.4, "PARTIAL_OVERLAP_BENIGN"
    return 0.0, "DIFFERENT_TOOL_PROPOSED"


def evaluate_behavioral_signal(
    original_action: CandidateAction,
    reexecutor: AgentReExecutor,
    observations: list[Observation],
    conversation_history: list[dict],
    *,
    masked_task: str | None = None,
    timeout_seconds: float = BEHAVIORAL_REEXECUTION_TIMEOUT_SECONDS,
) -> BehavioralSignal:
    """Mask the task, call the re-execution oracle under a wall-clock timeout,
    score the result structurally, and return a BehavioralSignal.

    A timeout uses concurrent.futures.ThreadPoolExecutor rather than making
    this function (or decide()) async, since the rest of the policy engine is
    synchronous and the identity of the real AgentReExecutor implementation
    (and whether it blocks) is unknown to this module.
    """
    task = masked_task if masked_task is not None else mask_task("")
    started = time.monotonic()
    # Not used as a context manager: ``with ThreadPoolExecutor()`` calls
    # shutdown(wait=True) on exit, which would block until a hung/slow
    # reexecutor call finishes anyway -- defeating the point of the timeout.
    # shutdown(wait=False) lets a timed-out call's thread be abandoned so this
    # function returns promptly.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(
        reexecutor.propose_action_with_masked_task,
        observations,
        conversation_history,
        task,
    )
    try:
        masked_action = future.result(timeout=timeout_seconds)
    except NotConfiguredError as error:
        executor.shutdown(wait=False)
        elapsed = time.monotonic() - started
        return BehavioralSignal(
            triggered=False,
            similarity_score=0.0,
            masked_action=None,
            reason=f"{_UNAVAILABLE_PREFIX}:not_configured:{error}",
            latency_seconds=elapsed,
        )
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False)
        elapsed = time.monotonic() - started
        return BehavioralSignal(
            triggered=False,
            similarity_score=0.0,
            masked_action=None,
            reason=f"{_UNAVAILABLE_PREFIX}:timeout_after_{timeout_seconds}s",
            latency_seconds=elapsed,
        )
    executor.shutdown(wait=False)

    elapsed = time.monotonic() - started
    score, reason = _score_similarity(original_action, masked_action)
    triggered = score >= BEHAVIORAL_TRIGGER_THRESHOLD
    return BehavioralSignal(
        triggered=triggered,
        similarity_score=score,
        masked_action=masked_action,
        reason=reason,
        latency_seconds=elapsed,
    )


def is_signal_unavailable(signal: BehavioralSignal) -> bool:
    """True when evaluate_behavioral_signal could not reach a real verdict
    (oracle unconfigured or timed out), as opposed to a genuine healthy/attack
    verdict. policy.py uses this to apply the fail-open/fail-closed choice."""
    return signal.reason.startswith(_UNAVAILABLE_PREFIX)
