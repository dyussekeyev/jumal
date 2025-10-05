import json
from typing import Dict, Any, Optional

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
        
        Uses brace counting to handle nested objects correctly.
        
        Args:
            text: Text potentially containing JSON
            
        Returns:
            JSON string or None
        """
        # Find first opening brace
        start = text.find('{')
        if start == -1:
            return None
        
        # Count braces to find matching closing brace
        brace_count = 0
        i = start
        while i < len(text):
            if text[i] == '{':
                brace_count += 1
            elif text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    # Found matching closing brace
                    return text[start:i+1]
            i += 1
        
        # No matching closing brace found
        return None

    def build_prompt(self, system_prompt: str, aggregated: Dict[str, Any]) -> str:
        """
        Build LLM prompt from aggregated data with locale support.
        
        Args:
            system_prompt: System prompt from config
            aggregated: Aggregated VT data
            
        Returns:
            Full prompt string with locale context
        """
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
        system_with_locale = f"{system_prompt}\n\nUser interface locale: {locale_name}. Generate main analysis text in {locale_name}."
        
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
                # Re-serialize with ensure_ascii=False to preserve Unicode characters
                # Use compact separators to normalize output
                json_text = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'))
                # Remove only the first occurrence of the original JSON block
                free_text = full_response.replace(candidate, "", 1).strip()
            except Exception as e:
                self.logger.warning(f"JSON parse failed: {e}")
        
        return parsed, free_text
    
    def extract_json_pretty(self, full_response: str):
        """
        Extract JSON and free text from LLM response with pretty-printed JSON.
        
        Args:
            full_response: Full LLM response text
            
        Returns:
            Tuple of (parsed_json or None, pretty_json_str or None, free_text)
        """
        parsed = None
        pretty_json_str = None
        free_text = full_response
        
        # Use common extraction method
        candidate = self.extract_first_json_block(full_response)
        if candidate:
            try:
                parsed = json.loads(candidate)
                # Pretty-print with ensure_ascii=False to preserve Unicode characters
                pretty_json_str = json.dumps(parsed, ensure_ascii=False, indent=2)
                # Remove only the first occurrence of the original JSON block
                free_text = full_response.replace(candidate, "", 1).strip()
            except Exception as e:
                self.logger.warning(f"JSON parse failed: {e}")
        
        return parsed, pretty_json_str, free_text