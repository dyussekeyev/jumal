"""
Tests for the orchestrator's VT lookup:
- Never calls any upload endpoint
- Returns NOT_FOUND when VT returns 404
- Returns RATE_LIMITED on 429
- Returns ERROR on other failures
- Returns OK with data on success
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.local_static.orchestrator import FileAnalysisOrchestrator
from analysis.local_static.models import VTFileStatus


class FakeVTClient:
    """
    Minimal VT client stub that records which methods were called.
    Never has upload/submit methods – calling one would raise AttributeError.
    """

    UPLOAD_METHODS = ("upload_file", "submit_file", "post_file", "scan_file")

    def __init__(self, file_report_response, optional_response=None):
        self._file_report_response = file_report_response
        self._optional_response = optional_response or {"ok": True, "data": {}}
        self.called_methods = []

    def get_file_report(self, h):
        self.called_methods.append(("get_file_report", h))
        return self._file_report_response

    def get_behaviour(self, h):
        self.called_methods.append(("get_behaviour", h))
        return self._optional_response

    def get_behaviour_mitre_trees(self, h):
        self.called_methods.append(("get_behaviour_mitre_trees", h))
        return self._optional_response

    def get_comments(self, h, limit=20):
        self.called_methods.append(("get_comments", h))
        return self._optional_response


def _make_tmp_file(content=b"MZ\x90\x00" * 16):
    """Create a temporary file and return its path."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    f.write(content)
    f.close()
    return f.name


class TestVTHashOnly(unittest.TestCase):

    def _make_orchestrator(self, vt_client):
        """Create an orchestrator with docker disabled (is_docker_available=False)."""
        orch = FileAnalysisOrchestrator(vt_client=vt_client)
        orch.docker_runner.is_docker_available = MagicMock(return_value=False)
        return orch

    # ------------------------------------------------------------------
    # No upload methods are ever called
    # ------------------------------------------------------------------
    def test_no_upload_endpoint_called_on_success(self):
        """Orchestrator must never call upload/submit methods on VT client."""
        vt = FakeVTClient(
            file_report_response={"ok": True, "data": {"attributes": {}}}
        )
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            orch.run(path)
        finally:
            os.unlink(path)

        called_names = [name for name, _ in vt.called_methods]
        for upload_method in FakeVTClient.UPLOAD_METHODS:
            self.assertNotIn(
                upload_method,
                called_names,
                f"Upload method '{upload_method}' was called – this must never happen",
            )

    def test_no_upload_endpoint_called_on_404(self):
        """Orchestrator must not upload even when file is not found in VT."""
        vt = FakeVTClient(file_report_response={"ok": False, "status": 404})
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            orch.run(path)
        finally:
            os.unlink(path)

        called_names = [name for name, _ in vt.called_methods]
        for upload_method in FakeVTClient.UPLOAD_METHODS:
            self.assertNotIn(upload_method, called_names)

    def test_only_hash_lookup_endpoint_used(self):
        """Only get_file_report (and optional endpoints) should be called."""
        vt = FakeVTClient(
            file_report_response={"ok": True, "data": {"attributes": {}}}
        )
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            orch.run(path)
        finally:
            os.unlink(path)

        allowed = {"get_file_report", "get_behaviour",
                   "get_behaviour_mitre_trees", "get_comments"}
        called_names = set(name for name, _ in vt.called_methods)
        self.assertTrue(
            called_names.issubset(allowed),
            f"Unexpected VT methods called: {called_names - allowed}",
        )

    # ------------------------------------------------------------------
    # Status mapping
    # ------------------------------------------------------------------
    def test_returns_not_found_on_404(self):
        vt = FakeVTClient(file_report_response={"ok": False, "status": 404})
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.NOT_FOUND)
        self.assertIsNone(result.vt_raw)

    def test_returns_rate_limited_on_429(self):
        vt = FakeVTClient(file_report_response={"ok": False, "status": 429})
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.RATE_LIMITED)

    def test_returns_error_on_other_failure(self):
        vt = FakeVTClient(file_report_response={"ok": False, "status": 500})
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.ERROR)

    def test_returns_error_on_exception(self):
        """Exception from VT client should map to ERROR status."""
        vt = MagicMock()
        vt.get_file_report.side_effect = Exception("network timeout")
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.ERROR)
        self.assertIsNone(result.vt_raw)

    def test_returns_ok_with_data_on_success(self):
        vt = FakeVTClient(
            file_report_response={"ok": True, "data": {"attributes": {"size": 1234}}}
        )
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.OK)
        self.assertIsNotNone(result.vt_raw)
        self.assertIn("file_report", result.vt_raw)

    def test_skipped_when_no_vt_client(self):
        """Without a VT client, status must be SKIPPED."""
        orch = FileAnalysisOrchestrator(vt_client=None)
        orch.docker_runner.is_docker_available = MagicMock(return_value=False)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.SKIPPED)
        self.assertIsNone(result.vt_raw)

    # ------------------------------------------------------------------
    # Optional endpoints are non-fatal
    # ------------------------------------------------------------------
    def test_optional_endpoint_failure_does_not_abort(self):
        """Failure in optional endpoints must not abort the pipeline."""
        vt = FakeVTClient(
            file_report_response={"ok": True, "data": {"attributes": {}}}
        )
        # Make optional endpoints raise
        vt.get_behaviour = MagicMock(side_effect=Exception("forbidden"))
        vt.get_behaviour_mitre_trees = MagicMock(side_effect=Exception("forbidden"))
        vt.get_comments = MagicMock(side_effect=Exception("forbidden"))
        orch = self._make_orchestrator(vt)
        path = _make_tmp_file()
        try:
            result = orch.run(path)
        finally:
            os.unlink(path)
        self.assertEqual(result.vt_status, VTFileStatus.OK)
        self.assertIn("file_report", result.vt_raw)


if __name__ == "__main__":
    unittest.main()
