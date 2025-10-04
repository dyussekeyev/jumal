import json
import re
from typing import Dict, Any, Optional, Tuple, List

# Constants for IOC extraction
BEGIN_IOC_JSON = "BEGIN_IOC_JSON"
END_IOC_JSON = "END_IOC_JSON"

# IOC schema definition
IOC_SCHEMA = """{
  "process_names": [],        // Unique process/executable names
  "network_ips": [],          // IP addresses only
  "network_domains": [],      // Domain names (exclude IPs)
  "urls": [],                 // Full URLs with protocol
  "file_paths": [],           // File system paths
  "registry_keys": [],        // Registry keys/paths
  "mutexes": [],              // Mutex names
  "yara_rules": [],           // YARA rule names
  "sigma_rules": [],          // Sigma rule names/titles
  "other_iocs": []            // Any other indicators
}"""

# Regex to find JSON blocks (both with and without markers)
JSON_BLOCK_RE = re.compile(r"\{.*?\}", re.DOTALL)


class IOCExtractor:
    """
    Builds IOC extraction prompt and parses structured IOC JSON from LLM response.
    
    Second LLM pass dedicated to extracting Indicators of Compromise (IOCs)
    and YARA/Sigma rules from aggregated VT behavior data.
    
    Supports:
    - Configurable system prompt and prompt template
    - JSON markers (BEGIN_IOC_JSON/END_IOC_JSON)
    - Retry logic with repair prompt for malformed responses
    - Normalization (deduplication, truncation, limits)
    """
    
    def __init__(self, logger, config: Optional[Dict[str, Any]] = None):
        self.logger = logger
        self.config = config or {}
        
        # Load config or use defaults
        llm_cfg = self.config.get("llm", {})
        self.system_prompt = llm_cfg.get("ioc_system_prompt", 
            "You are a DFIR assistant. Extract only factual Indicators of Compromise.")
        self.prompt_template = llm_cfg.get("ioc_prompt_template",
            "### CONTEXT\n{CONTEXT}\n\n### OUTPUT\nReturn ONLY JSON between markers:\n"
            f"{BEGIN_IOC_JSON}\n{{SCHEMA}}\n{END_IOC_JSON}\n"
            "Rules:\n- Keep EXACT keys.\n- Strings only.\n- No duplicates.\n- Empty arrays as [].\n- No extra keys.")
        self.retry_enabled = llm_cfg.get("ioc_retry_enabled", True)
        self.use_json_mode = llm_cfg.get("use_json_mode", True)
    
    def _build_context(self, aggregated: Dict[str, Any]) -> str:
        """Build context section from aggregated data."""
        lines = []
        
        # Basic metadata
        basic = aggregated.get("basic", {})
        lines.append("FILE METADATA:")
        lines.append(f"- Detections: {basic.get('detections', 0)}")
        lines.append(f"- Type: {basic.get('type_description', 'unknown')}")
        lines.append(f"- Names: {', '.join(basic.get('names', [])[:10])}")
        lines.append("")
        
        # MITRE techniques
        mitre_list = aggregated.get("mitre", [])
        if mitre_list:
            lines.append(f"MITRE ATT&CK TECHNIQUES ({len(mitre_list)} total):")
            for t in mitre_list[:20]:
                lines.append(f"- {t}")
            lines.append("")
        
        # Processes (truncate to save tokens)
        processes = aggregated.get("processes", [])
        if processes:
            lines.append(f"PROCESSES ({len(processes)} total, showing first 50):")
            for p in processes[:50]:
                lines.append(f"- {p}")
            lines.append("")
        
        # Network indicators (truncate)
        network = aggregated.get("network", [])
        if network:
            lines.append(f"NETWORK INDICATORS ({len(network)} total, showing first 50):")
            for n in network[:50]:
                lines.append(f"- {n}")
            lines.append("")
        
        # Comments may contain IOCs
        comments = aggregated.get("comments", [])
        if comments:
            lines.append(f"COMMENTS ({len(comments)} total):")
            for c in comments[:10]:  # Limit to 10 comments to save tokens
                lines.append(f"- {c[:200]}")  # Truncate each comment
            lines.append("")
        
        # YARA rules
        yara_results = aggregated.get("yara_ruleset")
        if yara_results:
            lines.append("YARA RULES:")
            if isinstance(yara_results, list):
                for r in yara_results[:20]:  # Limit to 20
                    if isinstance(r, dict):
                        rule_name = r.get("rule_name") or r.get("rule") or r.get("name")
                        if rule_name:
                            lines.append(f"- {rule_name}")
            lines.append("")
        
        # Sigma rules
        sigma_results = aggregated.get("sigma_rules")
        if sigma_results:
            lines.append("SIGMA RULES:")
            if isinstance(sigma_results, list):
                for r in sigma_results[:20]:  # Limit to 20
                    if isinstance(r, dict):
                        rule_name = r.get("rule_name") or r.get("title") or r.get("name")
                        if rule_name:
                            lines.append(f"- {rule_name}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _build_prompts(self, aggregated: Dict[str, Any], json_mode: bool) -> Tuple[str, str]:
        """
        Build system and user prompts for IOC extraction.
        
        Args:
            aggregated: Aggregated VT data
            json_mode: Whether to use json_mode (affects marker inclusion)
            
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        context = self._build_context(aggregated)
        
        # Build user prompt from template
        user_prompt = self.prompt_template.replace("{CONTEXT}", context)
        user_prompt = user_prompt.replace("{SCHEMA}", IOC_SCHEMA)
        
        # If json_mode is enabled, we might not need markers (but include them anyway for clarity)
        # The markers help with parsing when json_mode is not available
        
        return self.system_prompt, user_prompt
    
    def _single_attempt(
        self,
        llm_client,
        system_prompt: str,
        user_prompt: str,
        model: str,
        temperature: float,
        timeout: Optional[int],
        json_mode: bool
    ) -> str:
        """
        Perform a single LLM call for IOC extraction.
        
        Args:
            llm_client: LLM client instance
            system_prompt: System prompt
            user_prompt: User prompt
            model: Model to use
            temperature: Temperature setting
            timeout: Optional timeout
            json_mode: Whether to use json_mode
            
        Returns:
            Raw LLM response text
        """
        # For now, we send only user prompt since complete_once doesn't support system messages
        # We prepend system prompt to user prompt
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        return llm_client.complete_once(
            prompt=full_prompt,
            model=model,
            temperature=temperature,
            timeout=timeout,
            json_mode=json_mode
        )
    
    def run(self, llm_client, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate IOC extraction with optional retry.
        
        Args:
            llm_client: LLM client instance
            aggregated: Aggregated VT data
            
        Returns:
            Dict with IOC results or error info:
            - On success: {"iocs": {...}, "raw_response": "...", "attempts": N}
            - On failure: {"error": "...", "raw_response": "...", "attempts": N}
        """
        llm_cfg = self.config.get("llm", {})
        ioc_model = llm_cfg.get("ioc_model") or llm_cfg.get("model", "gpt-4o-mini")
        
        system_prompt, user_prompt = self._build_prompts(aggregated, self.use_json_mode)
        
        # First attempt
        self.logger.info(f"IOC extraction attempt 1 with model: {ioc_model}")
        try:
            response = self._single_attempt(
                llm_client,
                system_prompt,
                user_prompt,
                ioc_model,
                temperature=0.0,
                timeout=None,
                json_mode=self.use_json_mode
            )
            
            # Try to parse
            ioc_data, error_msg = self._parse_and_normalize(response)
            
            if ioc_data:
                self.logger.info("IOC extraction successful on first attempt")
                return {
                    "iocs": ioc_data,
                    "raw_response": response[:1000],  # Truncate for storage
                    "attempts": 1
                }
            
            # First attempt failed to parse
            self.logger.warning(f"First IOC parse failed: {error_msg}")
            
            # Retry if enabled
            if self.retry_enabled:
                self.logger.info("Attempting IOC extraction retry with repair prompt")
                repair_prompt = self._build_repair_prompt(response, error_msg)
                
                response2 = self._single_attempt(
                    llm_client,
                    system_prompt,
                    repair_prompt,
                    ioc_model,
                    temperature=0.0,
                    timeout=None,
                    json_mode=self.use_json_mode
                )
                
                ioc_data2, error_msg2 = self._parse_and_normalize(response2)
                
                if ioc_data2:
                    self.logger.info("IOC extraction successful on retry")
                    return {
                        "iocs": ioc_data2,
                        "raw_response": response2[:1000],
                        "attempts": 2
                    }
                
                self.logger.warning(f"Retry also failed: {error_msg2}")
                return {
                    "error": f"parse_failed_after_retry: {error_msg2}",
                    "raw_response": response2[:1000],
                    "attempts": 2
                }
            else:
                return {
                    "error": f"parse_failed: {error_msg}",
                    "raw_response": response[:1000],
                    "attempts": 1
                }
                
        except Exception as e:
            self.logger.exception("IOC extraction LLM call failed")
            return {
                "error": f"llm_call_failed: {str(e)}",
                "raw_response": "",
                "attempts": 1
            }
    
    def _build_repair_prompt(self, failed_response: str, error_msg: str) -> str:
        """Build a repair prompt for retry attempt."""
        return (
            f"The previous response failed to parse: {error_msg}\n\n"
            f"Previous response (truncated):\n{failed_response[:500]}\n\n"
            f"Please provide a corrected JSON response with the exact structure:\n"
            f"{BEGIN_IOC_JSON}\n{IOC_SCHEMA}\n{END_IOC_JSON}\n\n"
            "Ensure:\n"
            "- Valid JSON syntax\n"
            "- All 10 required keys present\n"
            "- All values are arrays of strings\n"
            "- No extra keys or comments"
        )
    
    def _parse_and_normalize(self, full_text: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Parse IOC JSON from LLM response and normalize.
        
        Args:
            full_text: Full LLM response text
            
        Returns:
            Tuple of (normalized_dict or None, error_message)
        """
        # Try to extract JSON with markers first
        parsed_json = self._extract_json_with_markers(full_text)
        
        if not parsed_json:
            # Fall back to regex extraction
            parsed_json = self._extract_json_fallback(full_text)
        
        if not parsed_json:
            msg = "No valid JSON block found in IOC extraction response"
            self.logger.warning(msg)
            return None, msg
        
        # Validate and normalize
        try:
            normalized = self._normalize_ioc_data(parsed_json)
            return normalized, ""
        except Exception as e:
            msg = f"IOC normalization failed: {e}"
            self.logger.exception(msg)
            return None, msg
    
    def _extract_json_with_markers(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON between BEGIN_IOC_JSON and END_IOC_JSON markers."""
        if BEGIN_IOC_JSON not in text or END_IOC_JSON not in text:
            return None
        
        start_idx = text.find(BEGIN_IOC_JSON)
        end_idx = text.find(END_IOC_JSON, start_idx)
        
        if start_idx == -1 or end_idx == -1:
            return None
        
        # Extract text between markers
        json_text = text[start_idx + len(BEGIN_IOC_JSON):end_idx].strip()
        
        try:
            return json.loads(json_text)
        except json.JSONDecodeError:
            return None
    
    def _extract_json_fallback(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract first JSON object using regex."""
        match = JSON_BLOCK_RE.search(text)
        if not match:
            return None
        
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    
    def _normalize_ioc_data(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize IOC data: validate keys, deduplicate, limit items, truncate strings.
        
        Args:
            parsed: Raw parsed JSON dict
            
        Returns:
            Normalized dict
            
        Raises:
            ValueError if structure is invalid
        """
        required_keys = [
            "process_names", "network_ips", "network_domains", "urls",
            "file_paths", "registry_keys", "mutexes", 
            "yara_rules", "sigma_rules", "other_iocs"
        ]
        
        # Ensure all required keys exist and are lists
        for key in required_keys:
            if key not in parsed:
                parsed[key] = []
            if not isinstance(parsed[key], list):
                parsed[key] = []
        
        # Normalize each list: dedupe, limit, truncate
        for key in required_keys:
            unique_items = []
            seen = set()
            
            for item in parsed[key][:100]:  # Max 100 items per category
                # Convert to string and clean
                item_str = str(item).strip()
                
                # Truncate to max 300 chars
                if len(item_str) > 300:
                    item_str = item_str[:300]
                
                # Add if non-empty and not seen
                if item_str and item_str not in seen:
                    unique_items.append(item_str)
                    seen.add(item_str)
            
            parsed[key] = unique_items
        
        return parsed
    
    # Legacy methods for backward compatibility
    def build_ioc_prompt(self, aggregated: Dict[str, Any]) -> str:
        """
        Build IOC extraction prompt (legacy method for backward compatibility).
        
        Args:
            aggregated: Aggregated VT data structure
            
        Returns:
            Prompt string for LLM
        """
        system_prompt, user_prompt = self._build_prompts(aggregated, self.use_json_mode)
        return f"{system_prompt}\n\n{user_prompt}"
    
    def parse_ioc_json(self, full_text: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Parse IOC JSON from LLM response (legacy method for backward compatibility).
        
        Args:
            full_text: Full LLM response text
            
        Returns:
            Tuple of (parsed_json_dict or None, error_message)
        """
        return self._parse_and_normalize(full_text)
    
    def extract_first_json_block(self, text: str) -> Optional[str]:
        """
        Extract the first JSON block from text (helper method).
        
        Args:
            text: Text potentially containing JSON
            
        Returns:
            JSON string or None
        """
        match = JSON_BLOCK_RE.search(text)
        if match:
            return match.group(0)
        return None
