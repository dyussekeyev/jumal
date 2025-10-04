import json
import re
from typing import Dict, Any, Optional
from core.prompt_selector import select_system_prompt

JSON_BLOCK_RE = re.compile(r"\{.*?\}", re.DOTALL)

class Summarizer:
    def __init__(self, logger, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Summarizer with configuration.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config or {}
    
    def extract_first_json_block(self, text: str) -> Optional[str]:
        """
        Extract the first JSON block from text.
        
        Args:
            text: Text potentially containing JSON
            
        Returns:
            JSON string or None
        """
        match = JSON_BLOCK_RE.search(text)
        if match:
            return match.group(0)
        return None

    def build_prompt(self, system_prompt: str, aggregated: Dict[str, Any]) -> str:
        """
        Build LLM prompt from aggregated data with locale support.
        
        Args:
            system_prompt: System prompt from config (may be overridden by model-specific prompt)
            aggregated: Aggregated VT data
            
        Returns:
            Full prompt string with locale context
        """
        # Get model name to select appropriate prompt
        llm_cfg = self.config.get("llm", {})
        model_name = llm_cfg.get("model", "gpt-4o-mini")
        
        # Use prompt selector to get model-appropriate system prompt
        selected_system_prompt = select_system_prompt(self.config, model_name, system_prompt)
        
        # Get UI locale for language adaptation
        ui_locale = self.config.get("ui", {}).get("default_language", "en")
        locale_map = {
            "en": "English",
            "ru": "Russian",
            "kz": "Kazakh"
        }
        locale_name = locale_map.get(ui_locale, "English")
        
        b = aggregated.get("basic", {})
        lines = []
        lines.append("FILE SUMMARY:")
        lines.append(f"Detections: {b.get('detections')}")
        lines.append(f"Type: {b.get('type_description')}")
        lines.append(f"Size: {b.get('size')}")
        lines.append(f"Names: {', '.join(b.get('names', []))}")
        lines.append("")
        lines.append("MITRE TECHNIQUES:")
        for t in aggregated.get("mitre", []):
            lines.append(f"- {t}")
        lines.append("")
        lines.append("PROCESSES:")
        for p in aggregated.get("processes", []):
            lines.append(f"- {p}")
        lines.append("")
        lines.append("NETWORK:")
        for n in aggregated.get("network", []):
            lines.append(f"- {n}")
        lines.append("")
        lines.append("COMMENTS (up to 20):")
        for c in aggregated.get("comments", [])[:20]:
            lines.append(f"- {c}")
        lines.append("")
        lines.append("YARA (if any):")
        if aggregated.get("yara_ruleset"):
            lines.append(json.dumps(aggregated["yara_ruleset"])[:1000])
        else:
            lines.append("None")
        lines.append("")
        lines.append("SIGMA (if any):")
        if aggregated.get("sigma_rules"):
            lines.append(json.dumps(aggregated["sigma_rules"])[:1000])
        else:
            lines.append("None")
        lines.append("")
        lines.append("TASK:")
        lines.append(f"User interface locale: {locale_name}. Provide all narrative and explanatory text in {locale_name}, but keep service keys (verdict, confidence, etc.), hashes, technical indicators, and code blocks in their original form without translation.")
        lines.append("")
        lines.append("Return FIRST a strict JSON object with fields: verdict (malicious|suspicious|benign|unknown), confidence (0-100 integer), key_capabilities (list of short strings), mitre_techniques (list of technique IDs like T1059), recommended_actions (list), raw_summary (short technical paragraph).")
        lines.append(f"Then after the JSON, provide a detailed free-text analysis in {locale_name}.")
        user_prompt = "\n".join(lines)
        
        # Add locale context to system prompt
        system_with_locale = f"{selected_system_prompt}\n\nUser interface locale: {locale_name}. Generate main analysis text in {locale_name}."
        
        full_prompt = f"{system_with_locale}\n\n{user_prompt}"
        return full_prompt

    def extract_json_and_text(self, full_response: str):
        """
        Extract JSON and free text from LLM response.
        
        Args:
            full_response: Full LLM response text
            
        Returns:
            Tuple of (parsed_json or None, free_text)
        """
        parsed = None
        json_text = None
        free_text = full_response
        
        # Use common extraction method
        candidate = self.extract_first_json_block(full_response)
        if candidate:
            try:
                parsed = json.loads(candidate)
                json_text = candidate
                free_text = full_response.replace(candidate, "").strip()
            except Exception as e:
                self.logger.warning(f"JSON parse failed: {e}")
        
        return parsed, free_text