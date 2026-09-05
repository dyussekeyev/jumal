import copy
import json
import os
from typing import Any, Dict

# Shared locale code → display name mapping used across the application.
LOCALE_NAMES = {
    "en": "English",
    "ru": "Russian",
    "kz": "Kazakh",
}

DEFAULT_CONFIG = {
    "virustotal": {
        "api_key": "PUT_YOUR_VT_API_KEY_HERE",
        "base_url": "https://www.virustotal.com/api/v3",
        "min_interval_seconds": 15,
        "max_retries": 3,
        "retry_backoff_base": 5,
        "use_vt": True
    },
    "llm": {
        "provider_url": "https://openrouter.ai/api/v1",
        "api_key": "PUT_YOUR_LLM_API_KEY_HERE",
        "model": "meta-llama/llama-3.2-1b-instruct",
        "system_prompt": "You are a malware analysis assistant. Provide concise, structured malware assessments.",
        "stream_enabled": True,
        "ioc_model": null,
        "ioc_raw_system_prompt": "You are a DFIR (Digital Forensics and Incident Response) assistant specializing in malware analysis. Your task is to extract and present Indicators of Compromise (IOCs) from malware behavior data in a clear, structured markdown format. Focus on factual indicators only - no speculation or analysis.",
        "ioc_raw_user_template": "Based on the following malware behavior data, extract and organize all Indicators of Compromise into a clear markdown report.\n\n{CONTEXT}\n\nPlease organize the IOCs into the following sections using markdown headings (##). Include a brief introductory sentence, then list indicators using bullet points (-). If a section has no indicators, write \"(none found)\".\n\nIMPORTANT GUIDELINES:\n- List only indicators actually observed in the provided data - do not guess or extrapolate\n- Deduplicate indicators within each section (case-insensitive comparison)\n- Preserve the original casing of indicators in output\n- File Names: Just the filename (e.g., \"malware.exe\"), not the full path\n- File Paths: Complete paths (e.g., \"C:\\Windows\\Temp\\malware.exe\")\n- IP Addresses: Only numeric IP addresses (IPv4/IPv6)\n- Domains: Only domain names, not IPs\n- URLs: Complete HTTP/HTTPS URLs\n\nRequired sections:\n- ## File Names\n- ## Processes\n- ## Network IPs\n- ## Network Domains\n- ## URLs\n- ## File Paths\n- ## Registry Keys\n- ## Mutexes\n- ## YARA Rules\n- ## Sigma Rules\n- ## Other IOCs\n\nKeep the format clean and easy to copy. List each unique indicator once."
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
        
        Returns:
            bool: True if any changes were made, False otherwise
        """
        if self._config is None:
            return False
        
        changed = False
        llm = self._config.get("llm", {})
        if "llm" in self._config and isinstance(llm, dict):
            # If ioc_model is not set or empty, set it to model
            if "ioc_model" not in llm or llm.get("ioc_model") in (None, ""):
                model = llm.get("model", "meta-llama/llama-3.2-1b-instruct")
                self._config["llm"]["ioc_model"] = model
                changed = True
        
        return changed

    def load(self) -> Dict[str, Any]:
        # Ensure directory exists (in case path contains directories)
        dirpath = os.path.dirname(self.path)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
    
        if not os.path.exists(self.path):
            self._config = copy.deepcopy(DEFAULT_CONFIG)
            self._normalize()
            self.save()
        else:
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Validate that loaded config is a dict
                if not isinstance(loaded, dict):
                    # fallback to defaults
                    self._config = copy.deepcopy(DEFAULT_CONFIG)
                    self._normalize()
                    self.save()
                else:
                    self._config = loaded
                    if self._normalize():
                        self.save()
            except (json.JSONDecodeError, OSError):
                # On parse error or read error fallback to defaults
                self._config = copy.deepcopy(DEFAULT_CONFIG)
                self._normalize()
                self.save()
        return self._config

    def save(self):
        if self._config is None:
            return
        # Ensure parent directory exists
        dirpath = os.path.dirname(self.path)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
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
