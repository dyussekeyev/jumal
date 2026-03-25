"""
Tests for clients.llm_client – LLMClient initialization, streaming, completions, error handling.
"""

import json
import unittest
from unittest.mock import Mock, patch, MagicMock
import requests

from clients.llm_client import (
    LLMClient,
    LLMAuthError,
    LLMBadRequestError,
    LLMClientError,
    LLMServerError,
)


def _make_openai_client(**kwargs):
    defaults = dict(
        base_url="https://api.openai.com/v1",
        api_key="test-key",
        model="gpt-4",
        stream_enabled=True,
        timeout=30,
        logger=Mock(),
    )
    defaults.update(kwargs)
    return LLMClient(**defaults)


def _make_ollama_client(**kwargs):
    defaults = dict(
        base_url="http://localhost:11434",
        api_key="",
        model="llama3",
        stream_enabled=True,
        timeout=30,
        logger=Mock(),
    )
    defaults.update(kwargs)
    return LLMClient(**defaults)


class TestInit(unittest.TestCase):
    def test_openai_without_key_raises(self):
        with self.assertRaises(LLMAuthError):
            LLMClient(
                base_url="https://api.openai.com/v1",
                api_key="",
                model="gpt-4",
                stream_enabled=True,
                timeout=30,
                logger=Mock(),
            )

    def test_ollama_without_key_ok(self):
        client = _make_ollama_client()
        self.assertTrue(client._is_ollama)

    def test_is_ollama_detection(self):
        client = _make_ollama_client()
        self.assertTrue(client._is_ollama)

        client2 = _make_openai_client()
        self.assertFalse(client2._is_ollama)


class TestRaiseHttpError(unittest.TestCase):
    def test_401_raises_auth(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Unauthorized"
        with self.assertRaises(LLMAuthError):
            client._raise_http_error(resp)

    def test_403_raises_auth(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Forbidden"
        with self.assertRaises(LLMAuthError):
            client._raise_http_error(resp)

    def test_400_raises_bad_request(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "Bad Request"
        with self.assertRaises(LLMBadRequestError):
            client._raise_http_error(resp)

    def test_404_raises_bad_request(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        with self.assertRaises(LLMBadRequestError):
            client._raise_http_error(resp)

    def test_500_raises_server_error(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"
        with self.assertRaises(LLMServerError):
            client._raise_http_error(resp)

    def test_unexpected_status_raises_generic(self):
        client = _make_openai_client()
        resp = MagicMock()
        resp.status_code = 418
        resp.text = "I'm a teapot"
        with self.assertRaises(LLMClientError):
            client._raise_http_error(resp)


class TestStreamOpenAI(unittest.TestCase):
    @patch("requests.post")
    def test_streaming_success(self, mock_post):
        client = _make_openai_client(stream_enabled=True)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_resp.iter_lines.return_value = [
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"content":" World"}}]}',
            "data: [DONE]",
        ]
        mock_post.return_value = mock_resp

        result = list(client.stream_chat("test"))
        self.assertEqual(result, ["Hello", " World"])

    @patch("requests.post")
    def test_non_streaming_success(self, mock_post):
        client = _make_openai_client(stream_enabled=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Full response"}}]
        }
        mock_post.return_value = mock_resp

        result = list(client.stream_chat("test"))
        self.assertEqual(result, ["Full response"])

    @patch("requests.post")
    def test_http_error_during_stream(self, mock_post):
        client = _make_openai_client(stream_enabled=True)
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Server Error"
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_post.return_value = mock_resp

        with self.assertRaises(LLMServerError):
            list(client.stream_chat("test"))


class TestStreamOllama(unittest.TestCase):
    @patch("requests.post")
    def test_streaming_success(self, mock_post):
        client = _make_ollama_client(stream_enabled=True)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_resp.iter_lines.return_value = [
            json.dumps({"message": {"content": "Hi"}, "done": False}),
            json.dumps({"message": {"content": " there"}, "done": True}),
        ]
        mock_post.return_value = mock_resp

        result = list(client.stream_chat("test"))
        self.assertEqual(result, ["Hi", " there"])

    @patch("requests.post")
    def test_non_streaming_success(self, mock_post):
        client = _make_ollama_client(stream_enabled=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"message": {"content": "Full response"}}
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_post.return_value = mock_resp

        result = list(client.stream_chat("test"))
        self.assertEqual(result, ["Full response"])


class TestCompleteOnce(unittest.TestCase):
    @patch("requests.post")
    def test_openai_complete_once(self, mock_post):
        client = _make_openai_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "completion"}}]
        }
        mock_post.return_value = mock_resp

        result = client.complete_once("test prompt")
        self.assertEqual(result, "completion")

    @patch("requests.post")
    def test_openai_json_mode(self, mock_post):
        client = _make_openai_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"result": true}'}}]
        }
        mock_post.return_value = mock_resp

        client.complete_once("test prompt", json_mode=True)
        payload = mock_post.call_args[1]["json"]
        self.assertEqual(payload["response_format"], {"type": "json_object"})

    @patch("requests.post")
    def test_ollama_complete_once(self, mock_post):
        client = _make_ollama_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"message": {"content": "ollama response"}}
        mock_post.return_value = mock_resp

        result = client.complete_once("test prompt")
        self.assertEqual(result, "ollama response")

    @patch("requests.post")
    def test_timeout_raises(self, mock_post):
        client = _make_openai_client()
        mock_post.side_effect = requests.exceptions.Timeout("timed out")

        with self.assertRaises(LLMClientError) as ctx:
            client.complete_once("test")
        self.assertIn("timed out", str(ctx.exception))

    @patch("requests.post")
    def test_connection_error_raises(self, mock_post):
        client = _make_openai_client()
        mock_post.side_effect = requests.exceptions.ConnectionError("refused")

        with self.assertRaises(LLMClientError) as ctx:
            client.complete_once("test")
        self.assertIn("connection error", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
