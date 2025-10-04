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
        "provider_url": "https://openrouter.ai/api/v1",
        "api_key": "PUT_YOUR_LLM_API_KEY_HERE",
        "model": "meta-llama/llama-3.2-1b-instruct",
        "system_prompt": "You are a malware analysis assistant. Provide concise, structured malware assessments.",
        "stream_enabled": True
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

    def _normalize(self):
        """
        Normalize configuration values.
        
        Ensures ioc_model is set to model value if not specified.
        """
        if self._config is None:
            return
        
        llm = self._config.get("llm", {})
        if "llm" in self._config and isinstance(llm, dict):
            # If ioc_model is not set or empty, set it to model
            if "ioc_model" not in llm or llm.get("ioc_model") in (None, ""):
                model = llm.get("model", "meta-llama/llama-3.2-1b-instruct")
                self._config["llm"]["ioc_model"] = model

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            self._config = DEFAULT_CONFIG
            self._normalize()
            self.save()
        else:
            with open(self.path, "r", encoding="utf-8") as f:
                self._config = json.load(f)
            self._normalize()
            self.save()  # Save to persist normalized values
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
        self._normalize()
        self.save()