"""
Tests for core.logging – init_logging setup.
"""

import logging
import os
import tempfile
import unittest

from core.logging import init_logging


class TestInitLogging(unittest.TestCase):
    def test_creates_logger_with_correct_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"level": "DEBUG", "file": log_file}}
            logger = init_logging(config)
            self.assertEqual(logger.name, "jumal")

    def test_log_file_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"level": "INFO", "file": log_file}}
            # Clear any existing handlers
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            logger = init_logging(config)
            logger.info("test message")
            self.assertTrue(os.path.exists(log_file))

    def test_log_level_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"level": "WARNING", "file": log_file}}
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            logger = init_logging(config)
            self.assertEqual(logger.level, logging.WARNING)

    def test_creates_log_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "subdir", "test.log")
            config = {"logging": {"level": "INFO", "file": log_file}}
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            logger = init_logging(config)
            self.assertTrue(os.path.isdir(os.path.join(tmp, "subdir")))

    def test_default_config_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Override only the file path so we don't pollute the real logs dir
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"file": log_file}}
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            logger = init_logging(config)
            self.assertEqual(logger.level, logging.INFO)

    def test_invalid_level_defaults_to_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"level": "INVALID", "file": log_file}}
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            logger = init_logging(config)
            self.assertEqual(logger.level, logging.INFO)

    def test_handlers_not_duplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "test.log")
            config = {"logging": {"level": "INFO", "file": log_file}}
            jumal_logger = logging.getLogger("jumal")
            jumal_logger.handlers.clear()
            init_logging(config)
            handler_count = len(jumal_logger.handlers)
            init_logging(config)
            self.assertEqual(len(jumal_logger.handlers), handler_count)

    def tearDown(self):
        # Clean up handlers to avoid interference between tests
        jumal_logger = logging.getLogger("jumal")
        jumal_logger.handlers.clear()


if __name__ == "__main__":
    unittest.main()
