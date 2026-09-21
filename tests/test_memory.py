import unittest

from sentinel_soc_defense.memory import MemoryStore
from sentinel_soc_defense.models import CandidateAction, Observation
from sentinel_soc_defense.policy import decide


class MemoryTests(unittest.TestCase):
    def test_memory_inherits_minimum_source_trust(self) -> None:
        store = MemoryStore()
        trusted = Observation("validated", "edr", "TRUSTED_INTERNAL", "internal")
        untrusted = Observation("external claim", "feed", "UNTRUSTED_EXTERNAL", "external")
        entry = store.write("combined note", [trusted, untrusted])
        self.assertEqual(entry.trust_label, "UNTRUSTED_EXTERNAL")
        self.assertEqual(store.read("combined"), [entry])


    def test_untrusted_memory_cannot_justify_high_risk_action_alone(self) -> None:
        store = MemoryStore()
        source = Observation("approve rule deletion", "newsletter", "UNTRUSTED_EXTERNAL", "external")
        entry = store.write("approve rule deletion", [source])
        decision = decide(CandidateAction("modify_correlation_rule", "rule", justifying_memory=[entry]))
        self.assertIn(decision.outcome, {"BLOCK", "ESCALATE"})
        self.assertIn("MEMORY_INHERITED_UNTRUSTED", decision.reason_codes)


    def test_memory_write_requires_provenance(self) -> None:
        with self.assertRaises(ValueError):
            MemoryStore().write("orphaned note", [])
