"""
Tests for model-specific prompt selection functionality.

Validates that:
1. Llama 3.2 3B models use optimized prompts
2. Generic models use default prompts
3. Custom user prompts override defaults
4. Backward compatibility is maintained
"""

import sys
import logging
from core.prompt_selector import is_llama_3_2_3b, select_system_prompt, select_ioc_prompts
from core.summarizer import Summarizer
from core.ioc_extractor import IOCExtractor


def test_is_llama_3_2_3b():
    """Test Llama 3.2 3B model detection."""
    # Positive cases
    assert is_llama_3_2_3b("meta-llama/Llama-3.2-3B")
    assert is_llama_3_2_3b("meta-llama/Llama-3.2-3B-Instruct")
    assert is_llama_3_2_3b("llama-3.2-3b")
    assert is_llama_3_2_3b("Llama-3.2-3B")
    
    # Negative cases
    assert not is_llama_3_2_3b("gpt-4o-mini")
    assert not is_llama_3_2_3b("meta-llama/Llama-3.1-70B")
    assert not is_llama_3_2_3b("gemini-1.5-pro")
    assert not is_llama_3_2_3b("")
    assert not is_llama_3_2_3b(None)
    print("✓ test_is_llama_3_2_3b passed")


def test_select_system_prompt_llama():
    """Test that Llama 3.2 3B selects optimized prompt."""
    config = {
        "llm": {
            "model": "meta-llama/Llama-3.2-3B",
            "system_prompt_llama_3_2_3b": "Llama optimized prompt"
        }
    }
    
    result = select_system_prompt(config, "meta-llama/Llama-3.2-3B", "Default prompt")
    assert result == "Llama optimized prompt"
    assert "Llama optimized prompt" in result
    print("✓ test_select_system_prompt_llama passed")


def test_select_system_prompt_generic():
    """Test that generic models use default prompt."""
    config = {
        "llm": {
            "model": "gpt-4o-mini",
            "system_prompt": "Generic prompt"
        }
    }
    
    result = select_system_prompt(config, "gpt-4o-mini", "Default prompt")
    assert result == "Generic prompt"
    print("✓ test_select_system_prompt_generic passed")


def test_select_system_prompt_custom_override():
    """Test that model-specific prompts take precedence over generic custom prompts for matching models."""
    # When using Llama model with Llama-specific prompt available, it should use Llama prompt
    config = {
        "llm": {
            "model": "meta-llama/Llama-3.2-3B",
            "system_prompt": "Generic custom prompt",
            "system_prompt_llama_3_2_3b": "Llama optimized prompt"
        }
    }
    
    # For Llama model, Llama-specific prompt takes precedence
    result = select_system_prompt(config, "meta-llama/Llama-3.2-3B", "Default prompt")
    assert result == "Llama optimized prompt"
    
    # For non-Llama model, use generic system_prompt
    result = select_system_prompt(config, "gpt-4o-mini", "Default prompt")
    assert result == "Generic custom prompt"
    
    print("✓ test_select_system_prompt_custom_override passed")


def test_select_ioc_prompts_llama():
    """Test that Llama 3.2 3B selects optimized IOC prompts."""
    config = {
        "llm": {
            "model": "meta-llama/Llama-3.2-3B",
            "ioc_raw_system_prompt_llama_3_2_3b": "Llama IOC system",
            "ioc_raw_user_template_llama_3_2_3b": "Llama IOC template"
        }
    }
    
    system, user = select_ioc_prompts(
        config,
        "meta-llama/Llama-3.2-3B",
        "Default IOC system",
        "Default IOC template"
    )
    
    assert system == "Llama IOC system"
    assert user == "Llama IOC template"
    print("✓ test_select_ioc_prompts_llama passed")


def test_select_ioc_prompts_generic():
    """Test that generic models use default IOC prompts."""
    config = {
        "llm": {
            "model": "gpt-4o-mini"
        }
    }
    
    system, user = select_ioc_prompts(
        config,
        "gpt-4o-mini",
        "Default IOC system",
        "Default IOC template"
    )
    
    assert system == "Default IOC system"
    assert user == "Default IOC template"
    print("✓ test_select_ioc_prompts_generic passed")


def test_summarizer_uses_llama_prompt():
    """Test that Summarizer picks Llama-specific prompt when model is Llama 3.2 3B."""
    logger = logging.getLogger("test")
    config = {
        "ui": {"default_language": "en"},
        "llm": {
            "model": "meta-llama/Llama-3.2-3B",
            "system_prompt_llama_3_2_3b": "LLAMA_OPTIMIZED_HEADER: You are optimized for Llama 3.2 3B."
        }
    }
    
    summ = Summarizer(logger, config)
    agg_struct = {
        "basic": {
            "detections": 5,
            "type_description": "Win32 EXE",
            "size": 12345,
            "names": ["sample.exe"]
        },
        "mitre": ["T1059"],
        "processes": ["cmd.exe"],
        "network": ["1.2.3.4"],
        "comments": ["Test"],
        "yara_ruleset": None,
        "sigma_rules": None
    }
    
    # Build prompt with generic system prompt, but it should use Llama-specific one
    prompt = summ.build_prompt("Generic system prompt", agg_struct)
    
    # Verify Llama-specific prompt is used
    assert "LLAMA_OPTIMIZED_HEADER" in prompt
    assert "optimized for Llama 3.2 3B" in prompt
    print("✓ test_summarizer_uses_llama_prompt passed")


def test_ioc_extractor_uses_llama_prompt():
    """Test that IOCExtractor uses specialized prompt when model matches Llama 3.2 3B."""
    logger = logging.getLogger("test")
    config = {
        "ui": {"default_language": "en"},
        "llm": {
            "model": "meta-llama/Llama-3.2-3B",
            "ioc_model": "meta-llama/Llama-3.2-3B",
            "ioc_raw_system_prompt_llama_3_2_3b": "LLAMA_IOC_OPTIMIZED: Extract IOCs efficiently.",
            "ioc_raw_user_template_llama_3_2_3b": "Llama IOC template with {CONTEXT}"
        }
    }
    
    extractor = IOCExtractor(logger, config)
    
    # Verify that the Llama-specific prompts are selected
    assert "LLAMA_IOC_OPTIMIZED" in extractor.raw_system_prompt
    assert "Llama IOC template" in extractor.raw_user_template
    print("✓ test_ioc_extractor_uses_llama_prompt passed")


def test_backward_compatibility():
    """Test that existing configs without Llama prompts still work."""
    logger = logging.getLogger("test")
    config = {
        "ui": {"default_language": "en"},
        "llm": {
            "model": "gpt-4o-mini",
            "system_prompt": "Legacy system prompt"
        }
    }
    
    summ = Summarizer(logger, config)
    agg_struct = {
        "basic": {
            "detections": 5,
            "type_description": "Win32 EXE",
            "size": 12345,
            "names": ["sample.exe"]
        },
        "mitre": [],
        "processes": [],
        "network": [],
        "comments": [],
        "yara_ruleset": None,
        "sigma_rules": None
    }
    
    prompt = summ.build_prompt("Legacy system prompt", agg_struct)
    assert "Legacy system prompt" in prompt
    
    extractor = IOCExtractor(logger, config)
    # Should use defaults since no custom prompts provided
    assert extractor.raw_system_prompt is not None
    assert extractor.raw_user_template is not None
    print("✓ test_backward_compatibility passed")


def run_all_tests():
    """Run all prompt selection tests."""
    print("\n=== Running Prompt Selection Tests ===\n")
    
    test_is_llama_3_2_3b()
    test_select_system_prompt_llama()
    test_select_system_prompt_generic()
    test_select_system_prompt_custom_override()
    test_select_ioc_prompts_llama()
    test_select_ioc_prompts_generic()
    test_summarizer_uses_llama_prompt()
    test_ioc_extractor_uses_llama_prompt()
    test_backward_compatibility()
    
    print("\n=== All Prompt Selection Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
