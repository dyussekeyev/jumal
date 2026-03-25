"""
Tests for core.summarizer – JSON extraction, prompt building, locale handling.
"""

import unittest
from unittest.mock import Mock

from core.summarizer import Summarizer


class TestExtractFirstJsonBlock(unittest.TestCase):
    def setUp(self):
        self.summarizer = Summarizer(Mock())

    def test_simple_object(self):
        text = 'Here is JSON: {"key": "value"} and more text.'
        result = self.summarizer.extract_first_json_block(text)
        self.assertEqual(result, '{"key": "value"}')

    def test_simple_array(self):
        text = 'Array: [1, 2, 3] end.'
        result = self.summarizer.extract_first_json_block(text)
        self.assertEqual(result, '[1, 2, 3]')

    def test_nested_objects(self):
        text = '{"outer": {"inner": true}}'
        result = self.summarizer.extract_first_json_block(text)
        self.assertEqual(result, '{"outer": {"inner": true}}')

    def test_escaped_quotes(self):
        text = r'{"msg": "say \"hello\""}'
        result = self.summarizer.extract_first_json_block(text)
        self.assertIsNotNone(result)
        self.assertIn("hello", result)

    def test_no_json(self):
        self.assertIsNone(self.summarizer.extract_first_json_block("no json here"))

    def test_empty_string(self):
        self.assertIsNone(self.summarizer.extract_first_json_block(""))

    def test_none_input(self):
        self.assertIsNone(self.summarizer.extract_first_json_block(None))

    def test_unmatched_brace(self):
        text = '{"key": "value"'
        self.assertIsNone(self.summarizer.extract_first_json_block(text))

    def test_string_with_braces(self):
        text = '{"msg": "contains { and } inside"}'
        result = self.summarizer.extract_first_json_block(text)
        self.assertEqual(result, '{"msg": "contains { and } inside"}')

    def test_first_block_extracted(self):
        text = '{"a": 1} {"b": 2}'
        result = self.summarizer.extract_first_json_block(text)
        self.assertEqual(result, '{"a": 1}')


class TestBuildPrompt(unittest.TestCase):
    def test_default_locale_english(self):
        summarizer = Summarizer(Mock(), config={"ui": {"default_language": "en"}})
        agg = {"basic": {}, "mitre": [], "processes": [], "network": [],
               "comments": [], "yara_ruleset": None, "sigma_rules": None}
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("English", prompt)
        self.assertIn("System", prompt)

    def test_locale_russian(self):
        summarizer = Summarizer(Mock(), config={"ui": {"default_language": "ru"}})
        agg = {"basic": {}, "mitre": [], "processes": [], "network": [],
               "comments": [], "yara_ruleset": None, "sigma_rules": None}
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("Russian", prompt)

    def test_locale_kazakh(self):
        summarizer = Summarizer(Mock(), config={"ui": {"default_language": "kz"}})
        agg = {"basic": {}, "mitre": [], "processes": [], "network": [],
               "comments": [], "yara_ruleset": None, "sigma_rules": None}
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("Kazakh", prompt)

    def test_unknown_locale_defaults_to_english(self):
        summarizer = Summarizer(Mock(), config={"ui": {"default_language": "xx"}})
        agg = {"basic": {}, "mitre": [], "processes": [], "network": [],
               "comments": [], "yara_ruleset": None, "sigma_rules": None}
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("English", prompt)

    def test_contains_all_sections(self):
        summarizer = Summarizer(Mock(), config={"ui": {"default_language": "en"}})
        agg = {
            "basic": {"detections": 5, "type_description": "EXE", "size": 1000, "names": ["test"]},
            "mitre": ["T1059"],
            "processes": ["cmd.exe"],
            "network": ["1.2.3.4"],
            "comments": ["Suspicious"],
            "yara_ruleset": [{"rule_name": "TestRule"}],
            "sigma_rules": None,
        }
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("FILE SUMMARY", prompt)
        self.assertIn("MITRE", prompt)
        self.assertIn("PROCESSES", prompt)
        self.assertIn("NETWORK", prompt)
        self.assertIn("COMMENTS", prompt)
        self.assertIn("YARA", prompt)
        self.assertIn("SIGMA", prompt)
        self.assertIn("TASK", prompt)

    def test_yara_none_shows_none_text(self):
        summarizer = Summarizer(Mock(), config={})
        agg = {"basic": {}, "mitre": [], "processes": [], "network": [],
               "comments": [], "yara_ruleset": None, "sigma_rules": None}
        prompt = summarizer.build_prompt("System", agg)
        self.assertIn("None", prompt)


class TestExtractJsonAndText(unittest.TestCase):
    def setUp(self):
        self.summarizer = Summarizer(Mock())

    def test_json_and_text(self):
        response = '{"verdict": "malicious"}\nThis is a trojan.'
        parsed, free_text = self.summarizer.extract_json_and_text(response)
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(free_text, "This is a trojan.")

    def test_no_json(self):
        response = "Just some text without JSON."
        parsed, free_text = self.summarizer.extract_json_and_text(response)
        self.assertIsNone(parsed)
        self.assertEqual(free_text, response)

    def test_pretty_mode(self):
        response = '{"verdict": "benign"}\nAll clear.'
        parsed, pretty, free_text = self.summarizer.extract_json_and_text(response, pretty=True)
        self.assertIsNotNone(parsed)
        self.assertIn('"verdict"', pretty)
        self.assertIn("benign", pretty)

    def test_pretty_mode_no_json(self):
        response = "No JSON here."
        parsed, pretty, free_text = self.summarizer.extract_json_and_text(response, pretty=True)
        self.assertIsNone(parsed)
        self.assertIsNone(pretty)


class TestExtractJsonPretty(unittest.TestCase):
    def test_wrapper(self):
        summarizer = Summarizer(Mock())
        response = '{"a": 1}\nText after.'
        parsed, pretty, free_text = summarizer.extract_json_pretty(response)
        self.assertEqual(parsed["a"], 1)
        self.assertIn('"a"', pretty)

    def test_unicode_preserved(self):
        summarizer = Summarizer(Mock())
        response = '{"msg": "Привет"}\nТекст.'
        parsed, pretty, free_text = summarizer.extract_json_pretty(response)
        self.assertIn("Привет", pretty)


if __name__ == "__main__":
    unittest.main()
