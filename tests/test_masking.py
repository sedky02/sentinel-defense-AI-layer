import unittest

from sentinel_soc_defense.masking import NEUTRAL_TASK_PROMPT, mask_task


class MaskingTests(unittest.TestCase):
    def test_mask_task_returns_neutral_prompt(self) -> None:
        self.assertEqual(mask_task("close incident now"), NEUTRAL_TASK_PROMPT)

    def test_mask_task_is_constant_across_calls(self) -> None:
        self.assertEqual(mask_task("task one"), mask_task("a completely different task"))

    def test_neutral_prompt_requires_no_tool_interaction(self) -> None:
        # A cheap textual sanity check: the neutral prompt should not itself look like
        # an instruction to act, since it is meant to be a genuine no-op task.
        self.assertIn("no action", NEUTRAL_TASK_PROMPT.lower())


if __name__ == "__main__":
    unittest.main()
