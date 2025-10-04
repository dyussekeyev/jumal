"""
Tests for IOC extraction prompt generation and marker-based parsing.
"""
from core.ioc_extractor import IOCExtractor, BEGIN_IOC_JSON, END_IOC_JSON, IOC_SCHEMA
import logging


def test_markers_in_prompt_without_json_mode():
    """Test that markers are included in prompt."""
    logger = logging.getLogger("test")
    config = {
        "llm": {
            "ioc_system_prompt": "Extract IOCs.",
            "ioc_prompt_template": f"Context: {{CONTEXT}}\nOutput:\n{BEGIN_IOC_JSON}\n{{SCHEMA}}\n{END_IOC_JSON}",
            "use_json_mode": False
        }
    }
    extractor = IOCExtractor(logger, config)
    
    aggregated = {
        "basic": {"detections": 5, "type_description": "EXE", "names": ["test.exe"]},
        "processes": ["cmd.exe"],
        "network": ["1.2.3.4"]
    }
    
    prompt = extractor.build_ioc_prompt(aggregated)
    
    # Verify markers are present
    assert BEGIN_IOC_JSON in prompt
    assert END_IOC_JSON in prompt
    assert "process_names" in prompt
    assert "cmd.exe" in prompt


def test_schema_includes_all_keys():
    """Test that IOC_SCHEMA constant includes all required keys."""
    required_keys = [
        "process_names", "network_ips", "network_domains", "urls",
        "file_paths", "registry_keys", "mutexes", 
        "yara_rules", "sigma_rules", "other_iocs"
    ]
    
    for key in required_keys:
        assert key in IOC_SCHEMA, f"Missing key: {key}"


def test_marker_extraction():
    """Test extraction of JSON between markers."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    response = f"""
    Some preamble text.
    
    {BEGIN_IOC_JSON}
    {{
      "process_names": ["test.exe"],
      "network_ips": ["1.1.1.1"],
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
    
    Some trailing text.
    """
    
    parsed, error = extractor.parse_ioc_json(response)
    
    assert parsed is not None, f"Parse failed: {error}"
    assert error == ""
    assert parsed["process_names"] == ["test.exe"]
    assert parsed["network_ips"] == ["1.1.1.1"]


def test_fallback_without_markers():
    """Test that fallback regex parsing works when markers are missing."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    response = """
    Here is the JSON you requested:
    {
      "process_names": ["fallback.exe"],
      "network_ips": [],
      "network_domains": [],
      "urls": [],
      "file_paths": [],
      "registry_keys": [],
      "mutexes": [],
      "yara_rules": [],
      "sigma_rules": [],
      "other_iocs": []
    }
    """
    
    parsed, error = extractor.parse_ioc_json(response)
    
    assert parsed is not None
    assert parsed["process_names"] == ["fallback.exe"]


def test_normalization_truncates_long_strings():
    """Test that normalization truncates strings longer than 300 chars."""
    logger = logging.getLogger("test")
    extractor = IOCExtractor(logger)
    
    long_string = "A" * 500
    response = f"""
    {{
      "process_names": ["{long_string}"],
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
    """
    
    parsed, error = extractor.parse_ioc_json(response)
    
    assert parsed is not None
    assert len(parsed["process_names"]) == 1
    assert len(parsed["process_names"][0]) == 300  # Should be truncated


def test_configurable_prompts():
    """Test that prompts can be customized via config."""
    logger = logging.getLogger("test")
    custom_system = "Custom system prompt"
    custom_template = "Custom template: {CONTEXT} | Schema: {SCHEMA}"
    
    config = {
        "llm": {
            "ioc_system_prompt": custom_system,
            "ioc_prompt_template": custom_template,
            "use_json_mode": False
        }
    }
    
    extractor = IOCExtractor(logger, config)
    
    aggregated = {"basic": {}, "processes": []}
    system_prompt, user_prompt = extractor._build_prompts(aggregated, False)
    
    assert system_prompt == custom_system
    assert "Custom template:" in user_prompt
    assert "Schema:" in user_prompt


if __name__ == "__main__":
    test_markers_in_prompt_without_json_mode()
    print("✓ test_markers_in_prompt_without_json_mode")
    
    test_schema_includes_all_keys()
    print("✓ test_schema_includes_all_keys")
    
    test_marker_extraction()
    print("✓ test_marker_extraction")
    
    test_fallback_without_markers()
    print("✓ test_fallback_without_markers")
    
    test_normalization_truncates_long_strings()
    print("✓ test_normalization_truncates_long_strings")
    
    test_configurable_prompts()
    print("✓ test_configurable_prompts")
    
    print("\nAll IOC prompt tests passed!")
