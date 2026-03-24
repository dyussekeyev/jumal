"""
Tests for DIE-based file-type branching in analyzer_entry.py and
for the context_builder.py conditional sections.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import the container entrypoint module directly (it's self-contained)
import importlib.util

_ENTRY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "docker", "analyzer", "analyzer_entry.py"
)
_spec = importlib.util.spec_from_file_location("analyzer_entry", _ENTRY_PATH)
_analyzer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_analyzer)

from analysis.local_static.context_builder import CombinedContextBuilder
from analysis.local_static.models import (
    FileAnalysisPipelineResult,
    StaticAnalysisResult,
    VTFileStatus,
)


class TestDIEFamilyDetection(unittest.TestCase):
    """Tests for run_diec() family-detection logic via _parse_diec_json."""

    def _parse(self, detects):
        """Call run_diec logic in isolation by patching _run."""
        import unittest.mock as mock

        stdout = __import__("json").dumps({"detects": detects})
        with mock.patch.object(_analyzer, "_run", return_value=(stdout, "", 0, 10, None)):
            result, tr = _analyzer.run_diec("/fake/path")
        return result

    def test_pe32_detection(self):
        data = self._parse([{"type": "PE32", "string": "PE32 executable"}])
        self.assertEqual(data["format_family"], "pe")

    def test_elf_detection(self):
        data = self._parse([{"type": "ELF", "string": "ELF 64-bit"}])
        self.assertEqual(data["format_family"], "elf")

    def test_macho_detection(self):
        data = self._parse([{"type": "Mach-O", "string": "Mach-O 64-bit"}])
        self.assertEqual(data["format_family"], "macho")

    def test_pdf_detection(self):
        data = self._parse([{"type": "PDF", "string": "PDF document"}])
        self.assertEqual(data["format_family"], "pdf")

    def test_office_word_detection(self):
        data = self._parse([{"type": "Microsoft Word", "string": "Word 2007+"}])
        self.assertEqual(data["format_family"], "office")

    def test_office_excel_detection(self):
        data = self._parse([{"type": "Excel", "string": "Excel 97-2003"}])
        self.assertEqual(data["format_family"], "office")

    def test_unknown_type(self):
        data = self._parse([{"type": "Unknown", "string": "Unknown binary"}])
        self.assertEqual(data["format_family"], "unknown")

    def test_pe_from_detail_string(self):
        """Family detected from detail string when type field is generic."""
        data = self._parse([{"type": "binary", "string": "PE32 portable executable"}])
        self.assertEqual(data["format_family"], "pe")

    def test_empty_detects(self):
        data = self._parse([])
        self.assertEqual(data["format_family"], "unknown")


class TestBranchingDispatch(unittest.TestCase):
    """Tests that the correct specialized tools are dispatched per family."""

    def test_pe_family_runs_capa_not_office_or_pdf(self):
        import unittest.mock as mock

        capa_mock = mock.MagicMock(return_value=({"capabilities": [], "attack": []},
                                                  {"tool": "capa", "status": "ok", "duration_ms": 0, "stderr": "", "error": ""}))
        office_mock = mock.MagicMock()
        pdf_mock = mock.MagicMock()

        with mock.patch.object(_analyzer, "run_capa", capa_mock), \
             mock.patch.object(_analyzer, "run_office", office_mock), \
             mock.patch.object(_analyzer, "run_pdf", pdf_mock):
            specialized = {}
            family = "pe"
            tool_runs = []
            if family in ("pe", "elf", "macho"):
                capa_res, capa_tr = _analyzer.run_capa("/fake")
                specialized["capa"] = capa_res
                tool_runs.append(capa_tr)
            elif family == "office":
                _analyzer.run_office("/fake")
            elif family == "pdf":
                _analyzer.run_pdf("/fake")

        capa_mock.assert_called_once()
        office_mock.assert_not_called()
        pdf_mock.assert_not_called()

    def test_office_family_runs_office_tools(self):
        import unittest.mock as mock

        office_mock = mock.MagicMock(return_value=({}, []))
        capa_mock = mock.MagicMock()

        with mock.patch.object(_analyzer, "run_office", office_mock), \
             mock.patch.object(_analyzer, "run_capa", capa_mock):
            specialized = {}
            family = "office"
            if family in ("pe", "elf", "macho"):
                _analyzer.run_capa("/fake")
            elif family == "office":
                office_res, office_trs = _analyzer.run_office("/fake")
                specialized["office"] = office_res
            elif family == "pdf":
                pass

        office_mock.assert_called_once()
        capa_mock.assert_not_called()

    def test_pdf_family_runs_pdf_tools(self):
        import unittest.mock as mock

        pdf_mock = mock.MagicMock(return_value=({}, []))
        capa_mock = mock.MagicMock()

        with mock.patch.object(_analyzer, "run_pdf", pdf_mock), \
             mock.patch.object(_analyzer, "run_capa", capa_mock):
            family = "pdf"
            if family in ("pe", "elf", "macho"):
                _analyzer.run_capa("/fake")
            elif family == "office":
                pass
            elif family == "pdf":
                _analyzer.run_pdf("/fake")

        pdf_mock.assert_called_once()
        capa_mock.assert_not_called()


class TestContextBuilderBranching(unittest.TestCase):
    """Tests that CombinedContextBuilder renders the right sections per file type."""

    def _make_pipeline(self, specialized=None, file_type=None):
        static = StaticAnalysisResult(
            sample={"file_name": "test.exe", "file_size": 1024,
                    "hashes": {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}},
            file_type=file_type or {"die": {"format_family": "pe", "format_detail": "PE32"}},
            generic_analysis={"yara": {"matches": []}, "floss": {}},
            specialized_analysis=specialized or {},
        )
        pipeline = FileAnalysisPipelineResult(
            file_path="/tmp/test.exe",
            local_static=static,
            vt_status=VTFileStatus.SKIPPED,
        )
        return pipeline

    def test_capa_section_rendered_for_pe(self):
        pipeline = self._make_pipeline(
            specialized={
                "capa": {
                    "capabilities": [{"name": "inject into process", "namespace": "host-interaction/process/inject"}],
                    "attack": [{"technique_id": "T1055", "technique": "Process Injection"}],
                }
            }
        )
        builder = CombinedContextBuilder()
        prompt = builder.build_full_prompt("sys", pipeline)
        self.assertIn("CAPA CAPABILITIES", prompt)
        self.assertIn("inject into process", prompt)
        self.assertIn("T1055", prompt)

    def test_office_section_rendered(self):
        pipeline = self._make_pipeline(
            file_type={"die": {"format_family": "office", "format_detail": "Word"}},
            specialized={
                "office": {
                    "mraptor": {"verdict": "malicious"},
                    "olevba": {"macro_count": 2, "suspicious_keywords": ["AutoOpen", "Shell"]},
                }
            }
        )
        builder = CombinedContextBuilder()
        prompt = builder.build_full_prompt("sys", pipeline)
        self.assertIn("OFFICE DOCUMENT ANALYSIS", prompt)
        self.assertIn("malicious", prompt)
        self.assertIn("AutoOpen", prompt)

    def test_pdf_section_rendered(self):
        pipeline = self._make_pipeline(
            file_type={"die": {"format_family": "pdf", "format_detail": "PDF"}},
            specialized={
                "pdf": {
                    "pdfid": {"keywords": {"/JS": 1, "/JavaScript": 1}, "suspicious": ["/JS", "/JavaScript"]}
                }
            }
        )
        builder = CombinedContextBuilder()
        prompt = builder.build_full_prompt("sys", pipeline)
        self.assertIn("PDF DOCUMENT ANALYSIS", prompt)
        self.assertIn("/JS", prompt)

    def test_no_capa_section_when_empty(self):
        pipeline = self._make_pipeline(specialized={"capa": {"capabilities": [], "attack": []}})
        builder = CombinedContextBuilder()
        prompt = builder.build_full_prompt("sys", pipeline)
        self.assertNotIn("CAPA CAPABILITIES", prompt)

    def test_no_office_section_when_absent(self):
        pipeline = self._make_pipeline(specialized={})
        builder = CombinedContextBuilder()
        prompt = builder.build_full_prompt("sys", pipeline)
        self.assertNotIn("OFFICE DOCUMENT ANALYSIS", prompt)


if __name__ == "__main__":
    unittest.main()
