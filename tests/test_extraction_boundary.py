import ast
import pathlib
import unittest


class ExtractionImportBoundaryTests(unittest.TestCase):
    """extraction.py must never import policy.py/risk_actions.py: those imports would
    give a quarantined, untrusted-text-handling module access to the action-registry
    and decision-making code it exists specifically to be walled off from. This is a
    static (AST-based) check, not a runtime sandbox: it catches an accidental
    top-level import but cannot stop a deliberately obfuscated dynamic import
    (importlib.import_module inside a function body). That's an acceptable trade-off
    given this repository's coding style, but it means the check is a regression
    guard, not a security boundary in its own right -- the real boundary is that
    nothing in extraction.py's public API ever calls into policy.py.
    """

    def test_extraction_module_does_not_import_policy_or_risk_actions(self) -> None:
        source_path = pathlib.Path(__file__).parent.parent / "sentinel_soc_defense" / "extraction.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        forbidden = {"policy", "risk_actions", "sentinel_soc_defense.policy", "sentinel_soc_defense.risk_actions"}
        violations = imported_modules & forbidden
        self.assertFalse(violations, f"extraction.py must not import {forbidden}, found {violations}")


if __name__ == "__main__":
    unittest.main()
