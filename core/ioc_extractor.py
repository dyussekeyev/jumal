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
    Extracts Indicators of Compromise (IOCs) from aggregated VT behavior data.
    
    Supports two modes:
    1. Raw mode (default): LLM outputs human-readable markdown sections.
       No JSON parsing, retry logic, or normalization.
    2. Legacy structured mode (deprecated): Returns error if attempted.
    
    Raw mode produces markdown with sections like:
    - Processes
    - Network IPs
    - Network Domains
    - URLs
    - File Paths
    - Registry Keys
    - Mutexes
    - YARA Rules
    - Sigma Rules
    - Other IOCs
    """
    
    # Default prompts for raw mode
    DEFAULT_RAW_SYSTEM_PROMPT = """You are a DFIR (Digital Forensics and Incident Response) assistant specializing in malware analysis.
Your task is to extract and present Indicators of Compromise (IOCs) from malware behavior data in a clear, structured markdown format.
Focus on factual indicators only - no speculation or analysis."""

    DEFAULT_RAW_USER_TEMPLATE = """Based on the following malware behavior data, extract and organize all Indicators of Compromise into a clear markdown report.

{CONTEXT}

Please organize the IOCs into the following sections using markdown headings (##). Include a brief introductory sentence, then list indicators using bullet points (-). If a section has no indicators, write "(none found)".

Required sections:
- ## Processes
- ## Network IPs
- ## Network Domains
- ## URLs
- ## File Paths
- ## Registry Keys
- ## Mutexes
- ## YARA Rules
- ## Sigma Rules
- ## Other IOCs

Keep the format clean and easy to copy. List each unique indicator once."""

    def __init__(self, logger, config: Optional[Dict[str, Any]] = None):
        self.logger = logger
        self.config = config or {}
        
        # Load config or use defaults
        llm_cfg = self.config.get("llm", {})
        
        # Check mode
        self.raw_mode = llm_cfg.get("ioc_raw_mode", True)
        
        if self.raw_mode:
            # Raw mode configuration
            self.raw_system_prompt = llm_cfg.get("ioc_raw_system_prompt", self.DEFAULT_RAW_SYSTEM_PROMPT)
            self.raw_user_template = llm_cfg.get("ioc_raw_user_template", self.DEFAULT_RAW_USER_TEMPLATE)
        else:
            # Legacy structured mode - deprecated
            self.logger.warning("Legacy structured IOC mode (ioc_raw_mode=false) is deprecated and no longer supported")
        
        # Legacy config keys (kept for backward compatibility but not used in raw mode)
        self.system_prompt = llm_cfg.get("ioc_system_prompt", 
            "You are a DFIR assistant. Extract only factual Indicators of Compromise.")
        self.prompt_template = llm_cfg.get("ioc_prompt_template",
            "### CONTEXT\n{CONTEXT}\n\n### OUTPUT\nReturn ONLY JSON between markers:\n"
            f"{BEGIN_IOC_JSON}\n{{SCHEMA}}\n{END_IOC_JSON}\n"
            "Rules:\n- Keep EXACT keys.\n- Strings only.\n- No duplicates.\n- Empty arrays as [].\n- No extra keys.")
        self.retry_enabled = llm_cfg.get("ioc_retry_enabled", True)
        self.use_json_mode = llm_cfg.get("use_json_mode", True)
    
    def _build_context(self, aggregated: Dict[str, Any]) -> str:
        """Build concise context section from aggregated data for IOC extraction."""
        lines = []
        
        # Basic metadata
        basic = aggregated.get("basic", {})
        lines.append("FILE METADATA:")
        lines.append(f"- Detections: {basic.get('detections', 0)}")
        lines.append(f"- Type: {basic.get('type_description', 'unknown')}")
        lines.append(f"- Names: {', '.join(basic.get('names', [])[:5])}")
        lines.append("")
        
        # MITRE techniques
        mitre_list = aggregated.get("mitre", [])
        if mitre_list:
            lines.append(f"MITRE ATT&CK TECHNIQUES ({len(mitre_list)} total, showing first 15):")
            for t in mitre_list[:15]:
                lines.append(f"- {t}")
            lines.append("")
        
        # Processes (truncate to save tokens)
        processes = aggregated.get("processes", [])
        if processes:
            lines.append(f"PROCESSES ({len(processes)} total, showing first 30):")
            for p in processes[:30]:
                lines.append(f"- {p}")
            lines.append("")
        
        # Network indicators (truncate)
        network = aggregated.get("network", [])
        if network:
            lines.append(f"NETWORK INDICATORS ({len(network)} total, showing first 30):")
            for n in network[:30]:
                lines.append(f"- {n}")
            lines.append("")
        
        # Comments may contain IOCs
        comments = aggregated.get("comments", [])
        if comments:
            lines.append(f"COMMENTS ({len(comments)} total, showing first 5):")
            for c in comments[:5]:  # Limit to 5 comments to save tokens
                lines.append(f"- {c[:150]}")  # Truncate each comment
            lines.append("")
        
        # YARA rules
        yara_results = aggregated.get("yara_ruleset")
        if yara_results:
            lines.append("YARA RULES DETECTED:")
            if isinstance(yara_results, list):
                for r in yara_results[:15]:  # Limit to 15
                    if isinstance(r, dict):
                        rule_name = r.get("rule_name") or r.get("rule") or r.get("name")
                        if rule_name:
                            lines.append(f"- {rule_name}")
            lines.append("")
        
        # Sigma rules
        sigma_results = aggregated.get("sigma_rules")
        if sigma_results:
            lines.append("SIGMA RULES DETECTED:")
            if isinstance(sigma_results, list):
                for r in sigma_results[:15]:  # Limit to 15
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
        Orchestrate IOC extraction.
        
        Args:
            llm_client: LLM client instance
            aggregated: Aggregated VT data
            
        Returns:
            Dict with IOC results or error info:
            - Raw mode success: {"raw_text": "...", "attempts": 1, "model": "..."}
            - Legacy mode: {"error": "legacy_mode_not_available", "attempts": 0}
            - Failure: {"error": "...", "raw_text": "", "attempts": 1}
        """
        llm_cfg = self.config.get("llm", {})
        ioc_model = llm_cfg.get("ioc_model") or llm_cfg.get("model", "gpt-4o-mini")
        
        # Check if legacy mode is requested
        if not self.raw_mode:
            self.logger.error("Legacy structured IOC mode is no longer supported")
            return {
                "error": "legacy_mode_not_available: Structured IOC extraction has been deprecated. Please use raw mode (set ioc_raw_mode=true or omit it from config).",
                "attempts": 0,
                "model": ioc_model
            }
        
        # Raw mode path
        self.logger.info(f"IOC raw extraction using model={ioc_model}")
        
        try:
            # Build context
            context = self._build_context(aggregated)
            
            # Build prompts
            user_prompt = self.raw_user_template.replace("{CONTEXT}", context)
            
            # Truncate if too long (rough estimate: 1 token ~= 4 chars)
            # Keep under 20k chars to be safe
            max_chars = 20000
            if len(user_prompt) > max_chars:
                self.logger.warning(f"User prompt too long ({len(user_prompt)} chars), truncating to {max_chars}")
                user_prompt = user_prompt[:max_chars] + "\n\n[... truncated for length ...]"
            
            # Combine system and user prompts for complete_once
            # LLMClient.complete_once expects a single prompt string
            combined_prompt = f"{self.raw_system_prompt}\n\n{user_prompt}"
            
            # Single LLM call, no JSON mode, no retry
            response = llm_client.complete_once(
                prompt=combined_prompt,
                model=ioc_model,
                temperature=0.0,
                timeout=None,
                json_mode=False
            )
            
            self.logger.info(f"IOC raw extraction completed successfully, response length: {len(response)} chars")
            
            return {
                "raw_text": response,
                "attempts": 1,
                "model": ioc_model
            }
            
        except Exception as e:
            self.logger.exception("IOC raw extraction LLM call failed")
            return {
                "error": f"llm_call_failed: {str(e)}",
                "raw_text": "",
                "attempts": 1,
                "model": ioc_model
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
