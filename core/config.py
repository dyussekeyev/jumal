import json
import os
from typing import Any, Dict

DEFAULT_CONFIG = {
    "virustotal": {
        "api_key": "PUT_YOUR_VT_API_KEY_HERE",
        "base_url": "https://www.virustotal.com/api/v3",
        "min_interval_seconds": 15,
        "max_retries": 3,
        "retry_backoff_base": 5
    },
    "llm": {
        "provider_url": "https://api.openai.com/v1",
        "api_key": "PUT_YOUR_LLM_API_KEY_HERE",
        "model": "gpt-4o-mini",
        "system_prompt": "You are a malware analysis assistant. Provide concise, structured malware assessments.",
        "stream_enabled": True,
        # Model-specific optimized prompts
        "system_prompt_llama_3_2_3b": """You are a malware analysis assistant optimized for efficient, accurate assessments.

CRITICAL RULES:
1. Output JSON FIRST (strict format, no markdown fences)
2. Use exact field names: verdict, confidence, key_capabilities, mitre_techniques, recommended_actions, raw_summary
3. NO speculation - only factual analysis from provided data
4. Keep responses token-efficient and focused
5. Avoid hallucination - if uncertain, state "unknown" or omit

After JSON, provide concise technical analysis.""",
        "ioc_raw_system_prompt_llama_3_2_3b": """You are a DFIR assistant specialized in IOC extraction.

RULES:
1. Extract ONLY factual indicators from provided data
2. Use markdown headings (##) for sections
3. List each unique indicator once with bullet points (-)
4. NO analysis or speculation
5. If section empty, write "(none found)"
6. Keep output clean and copy-ready""",
        "ioc_raw_user_template_llama_3_2_3b": """Extract IOCs from malware behavior data below. Organize into markdown sections.

{CONTEXT}

Required sections:
## Processes
## Network IPs
## Network Domains
## URLs
## File Paths
## Registry Keys
## Mutexes
## YARA Rules
## Sigma Rules
## Other IOCs

Format: Brief intro, then bullet list (-) of unique indicators. Write "(none found)" for empty sections."""
    },
    "ui": {
        "default_language": "en"
    },
    "network": {
        "request_timeout_seconds": 30,
        "user_agent": "JUMAL/0.1"
    },
    "output": {
        "directory": "reports"
    },
    "logging": {
        "level": "INFO",
        "file": "logs/app.log"
    }
}

class ConfigManager:
    def __init__(self, path: str):
        self.path = path
        self._config = None

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            self._config = DEFAULT_CONFIG
            self.save()
        else:
            with open(self.path, "r", encoding="utf-8") as f:
                self._config = json.load(f)
        return self._config

    def save(self):
        if self._config is None:
            return
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)

    def get(self) -> Dict[str, Any]:
        if self._config is None:
            return self.load()
        return self._config

    def update_from_dict(self, data: Dict[str, Any]):
        # shallow update for relevant keys
        cfg = self.get()
        for section, values in data.items():
            if section in cfg and isinstance(values, dict):
                cfg[section].update(values)
            else:
                cfg[section] = values
        self.save()