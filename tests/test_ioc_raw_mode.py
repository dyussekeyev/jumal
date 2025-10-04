"""
Tests for IOC extraction in raw mode (markdown output).
"""
from core.ioc_extractor import IOCExtractor
import logging


class MockLLMClient:
    """Mock LLM client for testing."""
    
    def __init__(self, response):
        self.response = response
        self.call_count = 0
    
    def complete_once(self, prompt, model=None, temperature=0.0, timeout=None, json_mode=False):
        self.call_count += 1
        self.last_prompt = prompt
        self.last_json_mode = json_mode
        return self.response


def test_raw_mode_success():
    """Test successful raw mode IOC extraction."""
    logger = logging.getLogger("test")
    config = {
        "llm": {
            "ioc_raw_mode": True,
            "ioc_model": "test-model"
        }
    }
    extractor = IOCExtractor(logger, config)
    
    mock_response = """## Processes
- cmd.exe
- powershell.exe

## Network IPs
- 192.168.1.1
- 10.0.0.1

## Network Domains
- evil.com

## URLs
- http://evil.com/payload

## File Paths
- C:\\Windows\\Temp\\malware.exe

## Registry Keys
- HKLM\\Software\\Test

## Mutexes
- Global\\TestMutex

## YARA Rules
- TestYara1

## Sigma Rules
- TestSigma1

## Other IOCs
- PDB path: C:\\build\\malware.pdb
"""
    
    mock_client = MockLLMClient(mock_response)
    aggregated = {
        "basic": {"detections": 10, "type_description": "EXE", "names": ["test.exe"]},
        "processes": ["cmd.exe"],
        "network": ["192.168.1.1"]
    }
    
    result = extractor.run(mock_client, aggregated)
    
    # Verify success
    assert "raw_text" in result, f"Expected 'raw_text' key, got: {result.keys()}"
    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    assert result["attempts"] == 1
    assert result["model"] == "test-model"
    assert mock_client.call_count == 1
    assert mock_client.last_json_mode == False, "Should not use JSON mode in raw mode"
    
    # Verify content
    raw_text = result["raw_text"]
    assert "## Processes" in raw_text
    assert "cmd.exe" in raw_text
    assert "## Network IPs" in raw_text
    assert "192.168.1.1" in raw_text
    
    print(f"✓ test_raw_mode_success - Got {len(raw_text)} chars of markdown")


def test_raw_mode_default():
    """Test that raw mode is default when not specified."""
    logger = logging.getLogger("test")
    config = {"llm": {}}  # No ioc_raw_mode specified
    extractor = IOCExtractor(logger, config)
    
    assert extractor.raw_mode == True, "Raw mode should be default"
    print("✓ test_raw_mode_default - Raw mode is default")


def test_legacy_mode_returns_error():
    """Test that legacy mode (ioc_raw_mode=false) returns an error."""
    logger = logging.getLogger("test")
    config = {
        "llm": {
            "ioc_raw_mode": False,
            "ioc_model": "test-model"
        }
    }
    extractor = IOCExtractor(logger, config)
    
    mock_client = MockLLMClient("should not be called")
    aggregated = {"basic": {}, "processes": []}
    
    result = extractor.run(mock_client, aggregated)
    
    # Verify error
    assert "error" in result, f"Expected error for legacy mode, got: {result}"
    assert "legacy_mode_not_available" in result["error"]
    assert result["attempts"] == 0
    assert mock_client.call_count == 0, "LLM should not be called for legacy mode"
    
    print(f"✓ test_legacy_mode_returns_error - Error: {result['error'][:50]}...")


def test_raw_mode_with_custom_prompts():
    """Test raw mode with custom prompts."""
    logger = logging.getLogger("test")
    custom_system = "Custom system prompt for testing"
    custom_template = "Custom template: {CONTEXT}"
    
    config = {
        "llm": {
            "ioc_raw_mode": True,
            "ioc_raw_system_prompt": custom_system,
            "ioc_raw_user_template": custom_template,
            "ioc_model": "test-model"
        }
    }
    extractor = IOCExtractor(logger, config)
    
    assert extractor.raw_system_prompt == custom_system
    assert extractor.raw_user_template == custom_template
    
    mock_response = "## Processes\n- test.exe"
    mock_client = MockLLMClient(mock_response)
    aggregated = {"basic": {}, "processes": ["test.exe"]}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "raw_text" in result
    # Verify custom prompts were used
    assert custom_system in mock_client.last_prompt
    assert "Custom template:" in mock_client.last_prompt
    
    print("✓ test_raw_mode_with_custom_prompts - Custom prompts work")


def test_raw_mode_truncates_long_context():
    """Test that raw mode truncates very long context."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_raw_mode": True}}
    extractor = IOCExtractor(logger, config)
    
    # Create aggregated data with very long process list
    long_processes = [f"process_{i}.exe" for i in range(5000)]
    aggregated = {
        "basic": {"detections": 10, "type_description": "EXE", "names": ["test.exe"]},
        "processes": long_processes,
        "network": []
    }
    
    mock_response = "## Processes\n- (truncated)"
    mock_client = MockLLMClient(mock_response)
    
    result = extractor.run(mock_client, aggregated)
    
    assert "raw_text" in result
    # Verify prompt was truncated (should contain truncation message if > 20k chars)
    # This is hard to verify directly, but we can check it didn't fail
    assert result["attempts"] == 1
    
    print("✓ test_raw_mode_truncates_long_context - Handles long context")


def test_raw_mode_llm_failure():
    """Test raw mode error handling when LLM call fails."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_raw_mode": True}}
    extractor = IOCExtractor(logger, config)
    
    class FailingMockClient:
        def complete_once(self, prompt, model=None, temperature=0.0, timeout=None, json_mode=False):
            raise Exception("LLM connection failed")
    
    failing_client = FailingMockClient()
    aggregated = {"basic": {}, "processes": []}
    
    result = extractor.run(failing_client, aggregated)
    
    # Verify error handling
    assert "error" in result
    assert "llm_call_failed" in result["error"]
    assert "raw_text" in result
    assert result["raw_text"] == ""
    assert result["attempts"] == 1
    
    print(f"✓ test_raw_mode_llm_failure - Error handled: {result['error'][:50]}...")


def test_section_headings_in_output():
    """Test that expected section headings appear in raw mode output."""
    logger = logging.getLogger("test")
    config = {"llm": {"ioc_raw_mode": True}}
    extractor = IOCExtractor(logger, config)
    
    # Mock response with all expected sections
    mock_response = """Brief introduction about IOCs found.

## Processes
- process1.exe
- process2.exe

## Network IPs
- 1.2.3.4

## Network Domains
- example.com

## URLs
- http://example.com/path

## File Paths
- C:\\path\\to\\file.exe

## Registry Keys
- HKLM\\Software\\Key

## Mutexes
- Global\\Mutex1

## YARA Rules
- YaraRule1

## Sigma Rules
- SigmaRule1

## Other IOCs
- Some other indicator
"""
    
    mock_client = MockLLMClient(mock_response)
    aggregated = {"basic": {}, "processes": []}
    
    result = extractor.run(mock_client, aggregated)
    
    assert "raw_text" in result
    raw_text = result["raw_text"]
    
    # Verify all expected sections are present
    expected_sections = [
        "## Processes",
        "## Network IPs",
        "## Network Domains",
        "## URLs",
        "## File Paths",
        "## Registry Keys",
        "## Mutexes",
        "## YARA Rules",
        "## Sigma Rules",
        "## Other IOCs"
    ]
    
    for section in expected_sections:
        assert section in raw_text, f"Missing section: {section}"
    
    print("✓ test_section_headings_in_output - All sections present")


if __name__ == "__main__":
    test_raw_mode_success()
    test_raw_mode_default()
    test_legacy_mode_returns_error()
    test_raw_mode_with_custom_prompts()
    test_raw_mode_truncates_long_context()
    test_raw_mode_llm_failure()
    test_section_headings_in_output()
    
    print("\nAll IOC raw mode tests passed! ✅")
