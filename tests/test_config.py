"""
Tests for core.config – ConfigManager load/save/normalize/update.
"""

import json
import os
import tempfile
import unittest

from core.config import ConfigManager, DEFAULT_CONFIG


class TestConfigLoad(unittest.TestCase):
    def test_creates_default_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertIn("virustotal", cfg)
            self.assertIn("llm", cfg)
            self.assertTrue(os.path.exists(path))

    def test_loads_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            custom = {"llm": {"model": "custom-model", "api_key": "k"}, "virustotal": {"api_key": "x"}}
            with open(path, "w") as f:
                json.dump(custom, f)
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertEqual(cfg["llm"]["model"], "custom-model")

    def test_malformed_json_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w") as f:
                f.write("not valid json{{{")
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertIn("virustotal", cfg)

    def test_non_dict_json_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w") as f:
                json.dump([1, 2, 3], f)
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertIn("virustotal", cfg)

    def test_creates_directories_if_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "subdir", "config.json")
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertTrue(os.path.exists(path))


class TestConfigNormalize(unittest.TestCase):
    def test_ioc_model_autofill(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cfg_data = {"llm": {"model": "my-model"}}
            with open(path, "w") as f:
                json.dump(cfg_data, f)
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertEqual(cfg["llm"]["ioc_model"], "my-model")

    def test_ioc_model_preserved_when_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cfg_data = {"llm": {"model": "model-a", "ioc_model": "model-b"}}
            with open(path, "w") as f:
                json.dump(cfg_data, f)
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertEqual(cfg["llm"]["ioc_model"], "model-b")

    def test_empty_ioc_model_gets_autofilled(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cfg_data = {"llm": {"model": "model-a", "ioc_model": ""}}
            with open(path, "w") as f:
                json.dump(cfg_data, f)
            cm = ConfigManager(path)
            cfg = cm.load()
            self.assertEqual(cfg["llm"]["ioc_model"], "model-a")


class TestConfigSave(unittest.TestCase):
    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm._config = {"test": True}
            cm.save()
            with open(path) as f:
                data = json.load(f)
            self.assertTrue(data["test"])

    def test_save_none_config_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm._config = None
            cm.save()
            self.assertFalse(os.path.exists(path))


class TestConfigGet(unittest.TestCase):
    def test_get_lazy_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cfg = cm.get()
            self.assertIn("virustotal", cfg)

    def test_get_returns_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm._config = {"cached": True}
            cfg = cm.get()
            self.assertTrue(cfg["cached"])


class TestConfigUpdate(unittest.TestCase):
    def test_update_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm.load()
            cm.update_from_dict({"llm": {"model": "updated-model"}})
            cfg = cm.get()
            self.assertEqual(cfg["llm"]["model"], "updated-model")

    def test_update_preserves_other_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm.load()
            cm.update_from_dict({"ui": {"default_language": "ru"}})
            cfg = cm.get()
            self.assertIn("virustotal", cfg)
            self.assertEqual(cfg["ui"]["default_language"], "ru")

    def test_update_new_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            cm = ConfigManager(path)
            cm.load()
            cm.update_from_dict({"custom": {"key": "value"}})
            cfg = cm.get()
            self.assertEqual(cfg["custom"]["key"], "value")


if __name__ == "__main__":
    unittest.main()
