"""
Utility for selecting model-specific prompts based on LLM model name.

Supports automatic prompt adaptation for:
- Llama 3.2 3B models (optimized for low parameter count, token efficiency)
- Generic/default prompts for other models
"""

from typing import Dict, Any, Optional


def is_llama_3_2_3b(model_name: str) -> bool:
    """
    Check if the model name matches Llama 3.2 3B pattern.
    
    Args:
        model_name: Model identifier string
        
    Returns:
        True if model is Llama 3.2 3B variant
    """
    if not model_name:
        return False
    model_lower = model_name.lower()
    return "meta-llama/llama-3.2-3b" in model_lower or "llama-3.2-3b" in model_lower


def select_system_prompt(config: Dict[str, Any], model_name: str, default_prompt: str) -> str:
    """
    Select appropriate system prompt based on model and configuration.
    
    Priority:
    1. Model-specific prompt if model matches (e.g., system_prompt_llama_3_2_3b for Llama 3.2 3B)
    2. User-provided custom system_prompt in config
    3. Default prompt
    
    Args:
        config: Full configuration dictionary
        model_name: Model identifier
        default_prompt: Default prompt to use as fallback
        
    Returns:
        Selected system prompt string
    """
    llm_cfg = config.get("llm", {})
    
    # If model is Llama 3.2 3B, try to get specialized prompt first
    if is_llama_3_2_3b(model_name):
        llama_prompt = llm_cfg.get("system_prompt_llama_3_2_3b")
        if llama_prompt:
            return llama_prompt
    
    # Fall back to custom prompt if provided, otherwise default
    custom_prompt = llm_cfg.get("system_prompt")
    return custom_prompt if custom_prompt else default_prompt


def select_ioc_prompts(config: Dict[str, Any], model_name: str, 
                      default_system: str, default_user_template: str) -> tuple[str, str]:
    """
    Select appropriate IOC extraction prompts based on model and configuration.
    
    Priority:
    1. Model-specific prompts if model matches (e.g., ioc_raw_system_prompt_llama_3_2_3b)
    2. User-provided custom prompts in config
    3. Default prompts
    
    Args:
        config: Full configuration dictionary
        model_name: Model identifier
        default_system: Default system prompt
        default_user_template: Default user template
        
    Returns:
        Tuple of (system_prompt, user_template)
    """
    llm_cfg = config.get("llm", {})
    
    # If model is Llama 3.2 3B, try to get specialized prompts first
    if is_llama_3_2_3b(model_name):
        llama_system = llm_cfg.get("ioc_raw_system_prompt_llama_3_2_3b")
        llama_user = llm_cfg.get("ioc_raw_user_template_llama_3_2_3b")
        
        if llama_system and llama_user:
            return llama_system, llama_user
    
    # Fall back to custom if provided, otherwise defaults
    custom_system = llm_cfg.get("ioc_raw_system_prompt")
    custom_user = llm_cfg.get("ioc_raw_user_template")
    
    system = custom_system if custom_system else default_system
    user_template = custom_user if custom_user else default_user_template
    
    return system, user_template
