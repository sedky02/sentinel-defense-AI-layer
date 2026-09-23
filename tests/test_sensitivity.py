import unittest

from sentinel_soc_defense.response_filter import filter_payload
from sentinel_soc_defense.sensitivity_registry import scan_text


class SensitivityTests(unittest.TestCase):
    def test_fingerprint_detects_and_redacts_secret(self) -> None:
        result = filter_payload({"content": "debug api_key=super-secret-value-123"})
        self.assertTrue(result["redacted"])
        self.assertEqual(result["content"], "debug [REDACTED_BY_SENTINEL]")
        self.assertIn("secret_assignment", result["findings"])

    def test_non_sensitive_context_is_preserved(self) -> None:
        result = filter_payload({"content": "host Server-22 returned status 200"})
        self.assertFalse(result["redacted"])
        self.assertEqual(result["content"], "host Server-22 returned status 200")

    def test_invalid_response_filter_payload_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            filter_payload({"value": "not an observation"})


if __name__ == "__main__":
    unittest.main()