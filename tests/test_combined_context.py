"""
Tests for CombinedContextBuilder – prompt structure and content.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.local_static.context_builder import CombinedContextBuilder, _compact_strings
from analysis.local_static.models import (
    FileAnalysisPipelineResult,
    StaticAnalysisResult,
    ToolRun,
    VTFileStatus,
)


def _make_static(**kwargs) -> StaticAnalysisResult:
    defaults = dict(
        sample={
            "file_name": "sample.exe",
            "file_size": 2048,
            "hashes": {
                "md5": "a" * 32,
                "sha1": "b" * 40,
                "sha256": "c" * 64,
            },
        },
        file_type={"die": {"format_family": "pe", "format_detail": "PE32 executable"}},
        generic_analysis={"yara": {"matches": []}, "floss": {}},
        specialized_analysis={},
        tool_runs=[],
        risk_hints=[],
        errors=[],
    )
    defaults.update(kwargs)
    return StaticAnalysisResult(**defaults)


def _make_pipeline(static=None, vt_status=VTFileStatus.SKIPPED, vt_raw=None) -> FileAnalysisPipelineResult:
    return FileAnalysisPipelineResult(
        file_path="/tmp/sample.exe",
        local_static=static or _make_static(),
        vt_status=vt_status,
        vt_raw=vt_raw,
    )


class TestCompactStrings(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(_compact_strings([]), [])

    def test_max_count_respected(self):
        strings = [f"benign_string_{i}" for i in range(100)]
        result = _compact_strings(strings, max_count=10)
        self.assertLessEqual(len(result), 10)

    def test_suspicious_strings_ranked_first(self):
        strings = ["hello", "world", "http://evil.example.com/payload", "benign"]
        result = _compact_strings(strings, max_count=4)
        self.assertEqual(result[0], "http://evil.example.com/payload")

    def test_multiple_suspicious_patterns(self):
        strings = [
            "powershell -enc base64data",   # 2 patterns
            "http://malware.example/",       # 1 pattern
            "CreateProcess notepad.exe",     # 1 pattern
            "random normal string",          # 0 patterns
        ]
        result = _compact_strings(strings, max_count=4)
        self.assertEqual(result[0], "powershell -enc base64data")


class TestBuildVTLines(unittest.TestCase):
    def setUp(self):
        self.builder = CombinedContextBuilder()

    def test_basic_vt_fields_present(self):
        agg = {
            "basic": {
                "detections": 42,
                "type_description": "PE32",
                "size": 12345,
                "names": ["malware.exe", "trojan.exe"],
            },
            "mitre": ["T1059 Command and Scripting Interpreter"],
            "processes": ["cmd.exe /c whoami"],
            "network": ["192.168.1.1"],
            "comments": ["Looks malicious"],
            "yara_ruleset": None,
            "sigma_rules": None,
        }
        lines = self.builder._build_vt_lines(agg)
        text = "\n".join(lines)
        self.assertIn("Detections: 42", text)
        self.assertIn("T1059", text)
        self.assertIn("cmd.exe /c whoami", text)
        self.assertIn("192.168.1.1", text)
        self.assertIn("Looks malicious", text)

    def test_yara_present(self):
        agg = {
            "basic": {"detections": 1, "type_description": None, "size": None, "names": []},
            "mitre": [], "processes": [], "network": [], "comments": [],
            "yara_ruleset": [{"rule_name": "Eicar_Test_Rule"}],
            "sigma_rules": None,
        }
        lines = self.builder._build_vt_lines(agg)
        text = "\n".join(lines)
        self.assertIn("Eicar_Test_Rule", text)

    def test_no_vt_data_fallback(self):
        pipeline = _make_pipeline(vt_status=VTFileStatus.NOT_FOUND)
        prompt = self.builder.build_full_prompt("system", pipeline, vt_aggregated=None)
        self.assertIn("NOT uploaded", prompt)

    def test_comments_capped_at_20(self):
        agg = {
            "basic": {"detections": 0, "type_description": None, "size": None, "names": []},
            "mitre": [], "processes": [], "network": [],
            "comments": [f"comment_{i}" for i in range(30)],
            "yara_ruleset": None, "sigma_rules": None,
        }
        lines = self.builder._build_vt_lines(agg)
        text = "\n".join(lines)
        # Only first 20 comments should be present
        self.assertIn("comment_19", text)
        self.assertNotIn("comment_20", text)


class TestBuildStaticLines(unittest.TestCase):
    def setUp(self):
        self.builder = CombinedContextBuilder()

    def test_hashes_rendered(self):
        static = _make_static()
        lines = self.builder._build_static_lines(static)
        text = "\n".join(lines)
        self.assertIn("MD5: " + "a" * 32, text)
        self.assertIn("SHA256: " + "c" * 64, text)

    def test_file_type_die_rendered(self):
        static = _make_static(
            file_type={"die": {"format_family": "pe", "format_detail": "PE32 executable"}}
        )
        lines = self.builder._build_static_lines(static)
        text = "\n".join(lines)
        self.assertIn("PE32 executable", text)
        self.assertIn("pe", text)

    def test_yara_hits_rendered(self):
        static = _make_static(
            generic_analysis={
                "yara": {"matches": [
                    {"rule": "Mirai_Botnet", "tags": ["malware", "botnet"]},
                ]},
                "floss": {},
            }
        )
        lines = self.builder._build_static_lines(static)
        text = "\n".join(lines)
        self.assertIn("LOCAL YARA HITS", text)
        self.assertIn("Mirai_Botnet", text)
        self.assertIn("botnet", text)

    def test_floss_strings_rendered(self):
        static = _make_static(
            generic_analysis={
                "yara": {"matches": []},
                "floss": {
                    "static_strings": ["http://c2.example.com/bot", "CreateProcess"],
                    "stack_strings": ["loaded_secret"],
                    "decoded_strings": [],
                }
            }
        )
        lines = self.builder._build_static_lines(static)
        text = "\n".join(lines)
        self.assertIn("SUSPICIOUS STRINGS", text)
        self.assertIn("http://c2.example.com/bot", text)
        self.assertIn("STACK STRINGS", text)
        self.assertIn("loaded_secret", text)

    def test_tool_warnings_rendered(self):
        static = _make_static(
            tool_runs=[
                ToolRun(tool="capa", status="timeout", duration_ms=180000, error="timed out"),
            ],
            errors=["Hash computation failed: disk error"],
        )
        lines = self.builder._build_static_lines(static)
        text = "\n".join(lines)
        self.assertIn("TOOL WARNINGS", text)
        self.assertIn("capa: timeout", text)
        self.assertIn("Hash computation failed", text)


class TestBuildFullPrompt(unittest.TestCase):
    def setUp(self):
        self.builder = CombinedContextBuilder()

    def test_contains_task_section(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("You are a malware analyst.", pipeline)
        self.assertIn("TASK:", prompt)
        self.assertIn("verdict", prompt)
        self.assertIn("confidence", prompt)

    def test_system_prompt_included(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("MY_SYSTEM_PROMPT", pipeline)
        self.assertIn("MY_SYSTEM_PROMPT", prompt)

    def test_locale_english(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("sys", pipeline, locale="en")
        self.assertIn("English", prompt)

    def test_locale_russian(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("sys", pipeline, locale="ru")
        self.assertIn("Russian", prompt)

    def test_locale_kazakh(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("sys", pipeline, locale="kz")
        self.assertIn("Kazakh", prompt)

    def test_vt_data_included_when_present(self):
        agg = {
            "basic": {"detections": 55, "type_description": "Trojan", "size": 4096, "names": []},
            "mitre": ["T1055"], "processes": [], "network": [],
            "comments": [], "yara_ruleset": None, "sigma_rules": None,
        }
        pipeline = _make_pipeline(vt_status=VTFileStatus.OK)
        prompt = self.builder.build_full_prompt("sys", pipeline, vt_aggregated=agg)
        self.assertIn("Detections: 55", prompt)
        self.assertIn("T1055", prompt)

    def test_pipeline_errors_included(self):
        pipeline = _make_pipeline()
        pipeline.pipeline_errors.append("Docker not available")
        prompt = self.builder.build_full_prompt("sys", pipeline)
        self.assertIn("PIPELINE WARNINGS", prompt)
        self.assertIn("Docker not available", prompt)

    def test_indicator_summary_hashes(self):
        pipeline = _make_pipeline()
        prompt = self.builder.build_full_prompt("sys", pipeline)
        self.assertIn("Hashes:", prompt)
        self.assertIn("md5: " + "a" * 32, prompt)

    def test_vt_status_in_indicator_summary(self):
        pipeline = _make_pipeline(vt_status=VTFileStatus.NOT_FOUND)
        prompt = self.builder.build_full_prompt("sys", pipeline)
        self.assertIn("Not found in VirusTotal", prompt)

    def test_no_local_static_section_when_absent(self):
        pipeline = FileAnalysisPipelineResult(
            file_path="/tmp/x.bin",
            local_static=None,
            vt_status=VTFileStatus.SKIPPED,
        )
        prompt = self.builder.build_full_prompt("sys", pipeline)
        self.assertNotIn("LOCAL STATIC ANALYSIS", prompt)

    def test_vt_skipped_status_note(self):
        pipeline = _make_pipeline(vt_status=VTFileStatus.SKIPPED)
        prompt = self.builder.build_full_prompt("sys", pipeline)
        self.assertIn("not queried", prompt)


if __name__ == "__main__":
    unittest.main()
