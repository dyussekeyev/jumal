"""
Test connection error handling in LLM client.
"""
import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from clients.llm_client import LLMClient, LLMClientError


def test_stream_openai_handles_chunked_encoding_error():
    """Test that ChunkedEncodingError is properly caught and converted to LLMClientError."""
    logger = Mock()
    client = LLMClient(
        base_url="https://api.example.com",
        api_key="test-key",
        model="test-model",
        stream_enabled=True,
        timeout=30,
        logger=logger
    )
    
    # Mock requests.post to raise ChunkedEncodingError
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        # Simulate ChunkedEncodingError during iter_lines
        mock_response.iter_lines.side_effect = requests.exceptions.ChunkedEncodingError(
            "Connection broken: ConnectionResetError(10054)"
        )
        mock_post.return_value = mock_response
        
        # Should raise LLMClientError
        with pytest.raises(LLMClientError) as exc_info:
            list(client.stream_chat("test prompt"))
        
        assert "Connection lost during streaming" in str(exc_info.value)
        logger.error.assert_called_once()


def test_stream_openai_handles_connection_reset_error():
    """Test that ConnectionResetError is properly caught and converted to LLMClientError."""
    logger = Mock()
    client = LLMClient(
        base_url="https://api.example.com",
        api_key="test-key",
        model="test-model",
        stream_enabled=True,
        timeout=30,
        logger=logger
    )
    
    # Mock requests.post to raise ConnectionResetError
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        # Simulate ConnectionResetError during iter_lines
        mock_response.iter_lines.side_effect = ConnectionResetError("Connection reset by peer")
        mock_post.return_value = mock_response
        
        # Should raise LLMClientError
        with pytest.raises(LLMClientError) as exc_info:
            list(client.stream_chat("test prompt"))
        
        assert "Connection lost during streaming" in str(exc_info.value)
        logger.error.assert_called_once()


def test_stream_ollama_handles_connection_errors():
    """Test that Ollama streaming also handles connection errors properly."""
    logger = Mock()
    client = LLMClient(
        base_url="http://localhost:11434",
        api_key="",
        model="test-model",
        stream_enabled=True,
        timeout=30,
        logger=logger
    )
    
    # Mock requests.post to raise ConnectionError
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        # Simulate ConnectionError during iter_lines
        mock_response.iter_lines.side_effect = requests.exceptions.ConnectionError(
            "Connection aborted"
        )
        mock_post.return_value = mock_response
        
        # Should raise LLMClientError
        with pytest.raises(LLMClientError) as exc_info:
            list(client.stream_chat("test prompt"))
        
        assert "Connection lost during streaming" in str(exc_info.value)
        logger.error.assert_called_once()
