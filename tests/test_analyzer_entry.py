"""
Tests for docker/analyzer/analyzer_entry.py – build_risk_hints after workaround removal.
"""

import os
import sys
import unittest
import importlib.util

# Import the container entrypoint module directly
_ENTRY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "docker", "analyzer", "analyzer_entry.py"
)
_spec = importlib.util.spec_from_file_location("analyzer_entry", _ENTRY_PATH)
_analyzer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_analyzer)


class TestBuildRiskHints(unittest.TestCase):
    """Tests for the simplified build_risk_hints function (string hints removed)."""

    def test_yara_match_hint(self):
        generic = {"yara": {"matches": [{"rule": "TestRule"}]}, "floss": {}}
        hints = _analyzer.build_risk_hints({}, generic, {})
        self.assertIn("yara_rules_matched", hints)

    def test_no_yara_no_hint(self):
        generic = {"yara": {"matches": []}, "floss": {}}
        hints = _analyzer.build_risk_hints({}, generic, {})
        self.assertNotIn("yara_rules_matched", hints)

    def test_capa_detected_hint(self):
        specialized = {"capa": {"capabilities": [{"name": "inject"}]}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertIn("capa_capabilities_detected", hints)

    def test_capa_error_no_hint(self):
        specialized = {"capa": {"error": "timeout", "capabilities": []}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertNotIn("capa_capabilities_detected", hints)

    def test_office_macro_suspicious(self):
        specialized = {"office": {"mraptor": {"verdict": "suspicious"}, "olevba": {}}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertIn("office_macro_suspicious", hints)

    def test_office_macro_malicious(self):
        specialized = {"office": {"mraptor": {"verdict": "malicious"}, "olevba": {}}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertIn("office_macro_malicious", hints)

    def test_office_suspicious_keywords(self):
        specialized = {"office": {"mraptor": {}, "olevba": {"suspicious_keywords": ["Shell"]}}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertIn("office_macro_suspicious_keywords", hints)

    def test_pdf_suspicious_indicators(self):
        specialized = {"pdf": {"pdfid": {"suspicious": ["/JS", "/JavaScript"]}}}
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, specialized)
        self.assertIn("pdf_suspicious_indicators", hints)

    def test_no_string_keyword_hints(self):
        """Verify that removed _STRING_HINTS keywords no longer produce hints."""
        # Even with strings that would have matched old _STRING_HINTS, no such hints appear
        generic = {
            "yara": {},
            "floss": {
                "static_strings": ["powershell", "cmd.exe", "http://evil.com",
                                   "VirtualAlloc", "base64"],
                "decoded_strings": [],
                "stack_strings": [],
            },
        }
        hints = _analyzer.build_risk_hints({}, generic, {})
        # These hints should NOT exist anymore
        self.assertNotIn("contains_powershell", hints)
        self.assertNotIn("contains_cmd_execution", hints)
        self.assertNotIn("contains_base64", hints)
        self.assertNotIn("contains_network_call", hints)
        self.assertNotIn("contains_process_injection", hints)
        self.assertNotIn("contains_persistence", hints)
        self.assertNotIn("packed_or_encrypted", hints)

    def test_empty_inputs(self):
        hints = _analyzer.build_risk_hints({}, {"yara": {}, "floss": {}}, {})
        self.assertEqual(hints, [])

    def test_combined_hints(self):
        """Multiple hints can be generated together."""
        generic = {"yara": {"matches": [{"rule": "R1"}]}, "floss": {}}
        specialized = {
            "capa": {"capabilities": [{"name": "inject"}]},
            "pdf": {"pdfid": {"suspicious": ["/JS"]}},
        }
        hints = _analyzer.build_risk_hints({}, generic, specialized)
        self.assertIn("yara_rules_matched", hints)
        self.assertIn("capa_capabilities_detected", hints)
        self.assertIn("pdf_suspicious_indicators", hints)


if __name__ == "__main__":
    unittest.main()
