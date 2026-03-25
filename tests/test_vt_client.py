"""
Tests for clients.vt_client – VTClient request handling, retries, error codes.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import requests

from clients.vt_client import (
    VTClient,
    VTAuthError,
    VTClientError,
    VTRateLimitError,
    VTServerError,
    VTUnexpectedStatus,
)


def _make_client(**kwargs):
    defaults = dict(
        api_key="test-key",
        base_url="https://www.virustotal.com/api/v3",
        min_interval=0,
        max_retries=1,
        backoff_base=0,
        timeout=10,
        user_agent="Test/1.0",
        logger=Mock(),
    )
    defaults.update(kwargs)
    return VTClient(**defaults)


class TestInit(unittest.TestCase):
    def test_empty_api_key_raises(self):
        with self.assertRaises(ValueError):
            _make_client(api_key="")

    def test_session_headers_set(self):
        client = _make_client()
        self.assertEqual(client.session.headers["x-apikey"], "test-key")


class TestRequest200(unittest.TestCase):
    def test_successful_json_response(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "abc"}}
        client.session.request = Mock(return_value=mock_resp)

        result = client._request("GET", "/files/abc")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["data"]["data"]["id"], "abc")

    def test_json_parse_error_retries(self):
        client = _make_client(max_retries=2, backoff_base=0)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTClientError) as ctx:
            client._request("GET", "/files/abc")
        self.assertIn("Invalid JSON", str(ctx.exception))


class TestRequest404(unittest.TestCase):
    def test_not_found(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        client.session.request = Mock(return_value=mock_resp)

        result = client._request("GET", "/files/nonexistent")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["error"], "not_found")


class TestRequestAuthErrors(unittest.TestCase):
    def test_401_raises_auth_error(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTAuthError):
            client._request("GET", "/files/abc")

    def test_403_raises_auth_error(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTAuthError):
            client._request("GET", "/files/abc")

    def test_400_raises_client_error(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTClientError):
            client._request("GET", "/files/abc")


class TestRequest429(unittest.TestCase):
    @patch("time.sleep")
    def test_rate_limit_retries_then_raises(self, mock_sleep):
        client = _make_client(max_retries=1, min_interval=0)
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTRateLimitError):
            client._request("GET", "/files/abc")


class TestRequest5xx(unittest.TestCase):
    @patch("time.sleep")
    def test_server_error_retries_then_raises(self, mock_sleep):
        client = _make_client(max_retries=2, backoff_base=0)
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTServerError):
            client._request("GET", "/files/abc")


class TestRequestNetworkError(unittest.TestCase):
    @patch("time.sleep")
    def test_network_error_retries(self, mock_sleep):
        client = _make_client(max_retries=2, backoff_base=0)
        client.session.request = Mock(side_effect=requests.ConnectionError("refused"))

        with self.assertRaises(VTClientError) as ctx:
            client._request("GET", "/files/abc")
        self.assertIn("Network error", str(ctx.exception))


class TestRequestUnexpectedStatus(unittest.TestCase):
    def test_unexpected_status_raises(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 418
        mock_resp.text = "I'm a teapot"
        client.session.request = Mock(return_value=mock_resp)

        with self.assertRaises(VTUnexpectedStatus):
            client._request("GET", "/files/abc")


class TestPublicAPI(unittest.TestCase):
    def test_get_file_report_calls_correct_path(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {}}
        client.session.request = Mock(return_value=mock_resp)

        client.get_file_report("abc123")
        args = client.session.request.call_args
        self.assertIn("/files/abc123", args[0][1])

    def test_get_behaviours_calls_correct_path(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {}}
        client.session.request = Mock(return_value=mock_resp)

        client.get_behaviours("abc123")
        args = client.session.request.call_args
        self.assertIn("/files/abc123/behaviours", args[0][1])

    def test_get_comments_limits_param(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {}}
        client.session.request = Mock(return_value=mock_resp)

        client.get_comments("abc123", limit=100)
        args = client.session.request.call_args
        self.assertEqual(args[1]["params"]["limit"], 40)

    def test_backward_compatible_aliases(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {}}
        client.session.request = Mock(return_value=mock_resp)

        client.get_behaviour("abc123")
        args = client.session.request.call_args
        self.assertIn("/files/abc123/behaviours", args[0][1])


class TestRateLimitSleep(unittest.TestCase):
    @patch("time.sleep")
    @patch("time.time")
    def test_sleep_enforced(self, mock_time, mock_sleep):
        client = _make_client(min_interval=5)
        mock_time.return_value = 100.0
        client._last_request_ts = 98.0  # 2 seconds ago, need 5

        client._rate_limit_sleep()
        mock_sleep.assert_called_once()
        # Should sleep ~3 seconds
        sleep_time = mock_sleep.call_args[0][0]
        self.assertAlmostEqual(sleep_time, 3.0, delta=0.1)


class TestBackoff(unittest.TestCase):
    @patch("time.sleep")
    def test_exponential_backoff(self, mock_sleep):
        client = _make_client(backoff_base=2)

        client._sleep_backoff(1)
        self.assertEqual(mock_sleep.call_args[0][0], 2)  # 2 * 2^0

        client._sleep_backoff(2)
        self.assertEqual(mock_sleep.call_args[0][0], 4)  # 2 * 2^1

        client._sleep_backoff(3)
        self.assertEqual(mock_sleep.call_args[0][0], 8)  # 2 * 2^2


if __name__ == "__main__":
    unittest.main()
