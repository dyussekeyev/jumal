from core.ioc_extractor import IOCExtractor
import logging
import json

def test_ioc_prompt_structure():
    """Test that IOC prompt contains required schema keywords."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    aggregated = {
        "basic": {
            "detections": 10,
            "type_description": "Win32 EXE",
            "names": ["malware.exe"]
        },
        "mitre": ["T1059 Command Execution"],
        "processes": ["cmd.exe", "powershell.exe"],
        "network": ["192.168.1.1", "evil.com"],
        "comments": ["Suspicious behavior detected"],
        "yara_ruleset": [{"rule_name": "MalwareRule"}],
        "sigma_rules": [{"title": "Suspicious Command"}]
    }
    
    prompt = extractor.build_ioc_prompt(aggregated)
    
    # Verify prompt contains expected structure
    assert "process_names" in prompt
    assert "network_ips" in prompt
    assert "network_domains" in prompt
    assert "urls" in prompt
    assert "file_paths" in prompt
    assert "registry_keys" in prompt
    assert "mutexes" in prompt
    assert "yara_rules" in prompt
    assert "sigma_rules" in prompt
    assert "other_iocs" in prompt
    assert "cmd.exe" in prompt
    assert "192.168.1.1" in prompt
    assert "MalwareRule" in prompt
    assert "JSON" in prompt


def test_ioc_json_parsing_valid():
    """Test parsing valid IOC JSON response."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    valid_json = '''
    {
      "process_names": ["cmd.exe", "powershell.exe"],
      "network_ips": ["192.168.1.1", "10.0.0.1"],
      "network_domains": ["evil.com", "malware.net"],
      "urls": ["http://evil.com/payload"],
      "file_paths": ["C:\\\\temp\\\\malware.exe"],
      "registry_keys": ["HKLM\\\\Software\\\\Malware"],
      "mutexes": ["Global\\\\MalwareMutex"],
      "yara_rules": ["Rule1", "Rule2"],
      "sigma_rules": ["SigmaRule1"],
      "other_iocs": ["PDB path"]
    }
    Some extra text after JSON
    '''
    
    parsed, error = extractor.parse_ioc_json(valid_json)
    
    assert parsed is not None
    assert error == ""
    assert parsed["process_names"] == ["cmd.exe", "powershell.exe"]
    assert parsed["network_ips"] == ["192.168.1.1", "10.0.0.1"]
    assert len(parsed["yara_rules"]) == 2


def test_ioc_json_parsing_malformed():
    """Test parsing malformed JSON."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    malformed = "This is not JSON at all"
    
    parsed, error = extractor.parse_ioc_json(malformed)
    
    assert parsed is None
    assert "No JSON block found" in error


def test_ioc_json_parsing_missing_keys():
    """Test that missing keys are filled with empty arrays."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    partial_json = '''
    {
      "process_names": ["cmd.exe"],
      "network_ips": ["192.168.1.1"]
    }
    '''
    
    parsed, error = extractor.parse_ioc_json(partial_json)
    
    assert parsed is not None
    assert error == ""
    assert parsed["process_names"] == ["cmd.exe"]
    assert parsed["network_domains"] == []  # Should be filled
    assert parsed["yara_rules"] == []  # Should be filled
    assert "mutexes" in parsed


def test_ioc_json_uniqueness():
    """Test that duplicate IOCs are removed."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    json_with_dupes = '''
    {
      "process_names": ["cmd.exe", "cmd.exe", "powershell.exe", "cmd.exe"],
      "network_ips": ["1.1.1.1", "1.1.1.1"],
      "network_domains": [],
      "urls": [],
      "file_paths": [],
      "registry_keys": [],
      "mutexes": [],
      "yara_rules": [],
      "sigma_rules": [],
      "other_iocs": []
    }
    '''
    
    parsed, error = extractor.parse_ioc_json(json_with_dupes)
    
    assert parsed is not None
    assert len(parsed["process_names"]) == 2  # Should remove duplicates
    assert "cmd.exe" in parsed["process_names"]
    assert "powershell.exe" in parsed["process_names"]
    assert len(parsed["network_ips"]) == 1


def test_extract_first_json_block():
    """Test extraction of first JSON block."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    text = 'Some text {"key": "value"} more text {"key2": "value2"}'
    
    json_str = extractor.extract_first_json_block(text)
    
    assert json_str is not None
    assert '{"key": "value"}' == json_str


if __name__ == "__main__":
    # Simple test runner
    test_ioc_prompt_structure()
    print("✓ test_ioc_prompt_structure")
    
    test_ioc_json_parsing_valid()
    print("✓ test_ioc_json_parsing_valid")
    
    test_ioc_json_parsing_malformed()
    print("✓ test_ioc_json_parsing_malformed")
    
    test_ioc_json_parsing_missing_keys()
    print("✓ test_ioc_json_parsing_missing_keys")
    
    test_ioc_json_uniqueness()
    print("✓ test_ioc_json_uniqueness")
    
    test_extract_first_json_block()
    print("✓ test_extract_first_json_block")
    
    print("\nAll tests passed!")
