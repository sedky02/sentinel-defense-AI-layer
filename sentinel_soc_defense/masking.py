"""Masking utility for MELON-style behavioral detection.

Replaces a user's real task/instruction with a fixed, neutral, no-op placeholder
so that a masked re-execution run can be compared against the original run while
holding observations constant. Only the *task* is masked -- observations/tool
outputs must never be altered, since divergence in tool-call proposal between
the original run and the masked run is the actual signal: if the agent proposes
the same action even when it has no real task driving it, the action must be
driven by content in the observations instead.
"""

from __future__ import annotations

NEUTRAL_TASK_PROMPT: str = (
    "Please wait and take no action; simply acknowledge receipt of the "
    "following context."
)
"""The fixed, task-neutral placeholder used for every masked re-execution.

Kept as a module constant (not inlined) so it can be tuned later -- e.g. to a
randomized/paraphrased neutral prompt -- without touching call sites or the
mask_task() contract that callers rely on."""


def mask_task(original_task: str) -> str:
    """Return the neutral task prompt, discarding the real user task.

    original_task is accepted (rather than the function taking no arguments)
    so call sites read naturally as "replace this task" and so a future,
    smarter masking strategy (e.g. task-category-aware neutral prompts) can
    be introduced without changing the function's signature."""
    return NEUTRAL_TASK_PROMPT
