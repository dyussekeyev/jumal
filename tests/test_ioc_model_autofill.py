"""
Test IOC model auto-fill behavior.

Verifies that when ioc_model is not set, missing, or empty,
it automatically gets set to the value of llm.model.
"""
import os
import json
import tempfile
from core.config import ConfigManager


def test_ioc_model_autofill_on_load_with_null():
    """Test that ioc_model is auto-filled when set to null in config file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "gpt-4",
                "ioc_model": None
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        loaded_config = manager.load()
        
        # ioc_model should be set to model value
        assert loaded_config["llm"]["ioc_model"] == "gpt-4"
        assert loaded_config["llm"]["model"] == "gpt-4"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_ioc_model_autofill_on_load_missing_key():
    """Test that ioc_model is auto-filled when key is missing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "claude-3"
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        loaded_config = manager.load()
        
        # ioc_model should be set to model value
        assert loaded_config["llm"]["ioc_model"] == "claude-3"
        assert loaded_config["llm"]["model"] == "claude-3"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_ioc_model_autofill_on_load_empty_string():
    """Test that ioc_model is auto-filled when set to empty string."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "llama-3.2",
                "ioc_model": ""
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        loaded_config = manager.load()
        
        # ioc_model should be set to model value
        assert loaded_config["llm"]["ioc_model"] == "llama-3.2"
        assert loaded_config["llm"]["model"] == "llama-3.2"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_ioc_model_preserved_when_set():
    """Test that ioc_model is preserved when explicitly set to a value."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "gpt-4",
                "ioc_model": "gpt-3.5-turbo"
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        loaded_config = manager.load()
        
        # ioc_model should remain as specified
        assert loaded_config["llm"]["ioc_model"] == "gpt-3.5-turbo"
        assert loaded_config["llm"]["model"] == "gpt-4"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_ioc_model_autofill_on_update():
    """Test that ioc_model is auto-filled when updating config with update_from_dict."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "gpt-4",
                "ioc_model": "gpt-4"
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        manager.load()
        
        # Update with ioc_model set to None
        manager.update_from_dict({
            "llm": {
                "model": "claude-3",
                "ioc_model": None
            }
        })
        
        updated_config = manager.get()
        
        # ioc_model should be auto-filled to new model value
        assert updated_config["llm"]["ioc_model"] == "claude-3"
        assert updated_config["llm"]["model"] == "claude-3"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_ioc_model_autofill_saved_to_file():
    """Test that auto-filled ioc_model is actually saved to the config file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "llm": {
                "model": "test-model",
                "ioc_model": None
            }
        }
        json.dump(config, f)
        config_path = f.name
    
    try:
        manager = ConfigManager(config_path)
        manager.load()
        
        # Read the file directly to verify it was saved
        with open(config_path, 'r', encoding='utf-8') as f:
            saved_config = json.load(f)
        
        assert saved_config["llm"]["ioc_model"] == "test-model"
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


if __name__ == "__main__":
    # Run tests
    print("Running IOC model auto-fill tests...")
    
    test_ioc_model_autofill_on_load_with_null()
    print("✓ test_ioc_model_autofill_on_load_with_null passed")
    
    test_ioc_model_autofill_on_load_missing_key()
    print("✓ test_ioc_model_autofill_on_load_missing_key passed")
    
    test_ioc_model_autofill_on_load_empty_string()
    print("✓ test_ioc_model_autofill_on_load_empty_string passed")
    
    test_ioc_model_preserved_when_set()
    print("✓ test_ioc_model_preserved_when_set passed")
    
    test_ioc_model_autofill_on_update()
    print("✓ test_ioc_model_autofill_on_update passed")
    
    test_ioc_model_autofill_saved_to_file()
    print("✓ test_ioc_model_autofill_saved_to_file passed")
    
    print("\nAll tests passed!")
