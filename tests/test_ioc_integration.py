"""
Integration test for IOCExtractor.run() method with retry logic.
"""
from core.ioc_extractor import IOCExtractor, BEGIN_IOC_JSON, END_IOC_JSON
import logging


class MockLLMClient:
    """Mock LLM client for testing."""
    
    def __init__(self, responses):
        self.responses = responses
        self.call_count = 0
    
    def complete_once(self, prompt, model=None, temperature=0.0, timeout=None, json_mode=False):
        if self.call_count < len(self.responses):
            response = self.responses[self.call_count]
            self.call_count += 1
            return response
        return "{}"


def test_run_success_first_attempt():
    """Test successful IOC extraction on first attempt."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_model": "test-model", "use_json_mode": True, "ioc_retry_enabled": True}}
    extractor = IOCExtractor(logger, config)
    
    valid_response = f"""
    {BEGIN_IOC_JSON}
    {{
      "process_names": ["test.exe"],
      "network_ips": ["1.1.1.1"],
      "network_domains": ["evil.com"],
      "urls": ["http://evil.com"],
      "file_paths": ["/tmp/test"],
      "registry_keys": ["HKLM\\\\Test"],
      "mutexes": ["TestMutex"],
      "yara_rules": ["YaraRule1"],
      "sigma_rules": ["SigmaRule1"],
      "other_iocs": ["Other"]
    }}
    {END_IOC_JSON}
    """
    
    mock_client = MockLLMClient([valid_response])
    aggregated = {"basic": {}, "processes": [], "network": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "iocs" in result, f"Expected 'iocs' key, got: {result}"
    assert result["attempts"] == 1
    assert result["iocs"]["process_names"] == ["test.exe"]
    assert result["iocs"]["network_ips"] == ["1.1.1.1"]
    print(f"✓ test_run_success_first_attempt - Result: {result['attempts']} attempts")


def test_run_retry_on_malformed():
    """Test retry logic when first attempt returns malformed JSON."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_model": "test-model", "use_json_mode": True, "ioc_retry_enabled": True}}
    extractor = IOCExtractor(logger, config)
    
    malformed_response = "This is not JSON at all"
    
    valid_response = f"""
    {BEGIN_IOC_JSON}
    {{
      "process_names": ["retry.exe"],
      "network_ips": [],
      "network_domains": [],
      "urls": [],
      "file_paths": [],
      "registry_keys": [],
      "mutexes": [],
      "yara_rules": [],
      "sigma_rules": [],
      "other_iocs": []
    }}
    {END_IOC_JSON}
    """
    
    mock_client = MockLLMClient([malformed_response, valid_response])
    aggregated = {"basic": {}, "processes": [], "network": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "iocs" in result, f"Expected retry to succeed, got: {result}"
    assert result["attempts"] == 2
    assert result["iocs"]["process_names"] == ["retry.exe"]
    print(f"✓ test_run_retry_on_malformed - Result: {result['attempts']} attempts")


def test_run_retry_disabled():
    """Test that retry is skipped when disabled."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_model": "test-model", "use_json_mode": True, "ioc_retry_enabled": False}}
    extractor = IOCExtractor(logger, config)
    
    malformed_response = "This is not JSON"
    
    mock_client = MockLLMClient([malformed_response])
    aggregated = {"basic": {}, "processes": [], "network": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "error" in result, f"Expected error, got: {result}"
    assert result["attempts"] == 1
    assert "parse_failed" in result["error"]
    print(f"✓ test_run_retry_disabled - Result: error after {result['attempts']} attempts")


def test_run_both_attempts_fail():
    """Test error reporting when both attempts fail."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_model": "test-model", "use_json_mode": True, "ioc_retry_enabled": True}}
    extractor = IOCExtractor(logger, config)
    
    malformed1 = "Bad JSON 1"
    malformed2 = "Bad JSON 2"
    
    mock_client = MockLLMClient([malformed1, malformed2])
    aggregated = {"basic": {}, "processes": [], "network": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "error" in result, f"Expected error, got: {result}"
    assert result["attempts"] == 2
    assert "parse_failed_after_retry" in result["error"]
    print(f"✓ test_run_both_attempts_fail - Result: error after {result['attempts']} attempts")


def test_normalization_deduplication():
    """Test that normalization removes duplicates."""
    logger = logging.getLogger("test")
    config = {"llm": {}}
    extractor = IOCExtractor(logger, config)
    
    response_with_dupes = f"""
    {BEGIN_IOC_JSON}
    {{
      "process_names": ["dup.exe", "dup.exe", "unique.exe", "dup.exe"],
      "network_ips": ["1.1.1.1", "1.1.1.1"],
      "network_domains": [],
      "urls": [],
      "file_paths": [],
      "registry_keys": [],
      "mutexes": [],
      "yara_rules": [],
      "sigma_rules": [],
      "other_iocs": []
    }}
    {END_IOC_JSON}
    """
    
    mock_client = MockLLMClient([response_with_dupes])
    aggregated = {"basic": {}, "processes": [], "network": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "iocs" in result
    assert len(result["iocs"]["process_names"]) == 2  # Should remove duplicates
    assert "dup.exe" in result["iocs"]["process_names"]
    assert "unique.exe" in result["iocs"]["process_names"]
    assert len(result["iocs"]["network_ips"]) == 1
    print(f"✓ test_normalization_deduplication - Deduplicated correctly")


if __name__ == "__main__":
    test_run_success_first_attempt()
    test_run_retry_on_malformed()
    test_run_retry_disabled()
    test_run_both_attempts_fail()
    test_normalization_deduplication()
    
    print("\nAll IOC integration tests passed!")
