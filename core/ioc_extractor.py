from typing import Dict, Any, Optional


class IOCExtractor:
    """
    Extracts Indicators of Compromise (IOCs) from aggregated VT behavior data.
    
    Uses raw mode: LLM outputs human-readable markdown sections.
    No JSON parsing, retry logic, or normalization required.
    
    Raw mode produces markdown with sections like:
    - File Names
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

IMPORTANT GUIDELINES:
- List only indicators actually observed in the provided data - do not guess or extrapolate
- Deduplicate indicators within each section (case-insensitive comparison)
- Preserve the original casing of indicators in output
- File Names: Just the filename (e.g., "malware.exe"), not the full path
- File Paths: Complete paths (e.g., "C:\\Windows\\Temp\\malware.exe")
- IP Addresses: Only numeric IP addresses (IPv4/IPv6)
- Domains: Only domain names, not IPs
- URLs: Complete HTTP/HTTPS URLs

Required sections:
- ## File Names
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
        """
        Initialize IOC extractor with configuration.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config or {}
        
        # Load config or use defaults
        llm_cfg = self.config.get("llm", {})
        
        # Raw mode configuration (always enabled)
        self.raw_system_prompt = llm_cfg.get("ioc_raw_system_prompt", self.DEFAULT_RAW_SYSTEM_PROMPT)
        self.raw_user_template = llm_cfg.get("ioc_raw_user_template", self.DEFAULT_RAW_USER_TEMPLATE)
    
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
        
        # File names (new)
        file_names = aggregated.get("file_names", [])
        if file_names:
            lines.append(f"FILE NAMES ({len(file_names)} total, showing first 30):")
            for fname in file_names[:30]:
                lines.append(f"- {fname}")
            lines.append("")
        
        # Processes (truncate to save tokens)
        processes = aggregated.get("processes", [])
        if processes:
            lines.append(f"PROCESSES ({len(processes)} total, showing first 30):")
            for p in processes[:30]:
                lines.append(f"- {p}")
            lines.append("")
        
        # File paths (new)
        file_paths = aggregated.get("file_paths", [])
        if file_paths:
            lines.append(f"FILE PATHS ({len(file_paths)} total, showing first 30):")
            for path in file_paths[:30]:
                lines.append(f"- {path}")
            lines.append("")
        
        # IP addresses (new - separated from domains)
        ip_addresses = aggregated.get("ip_addresses", [])
        if ip_addresses:
            lines.append(f"IP ADDRESSES ({len(ip_addresses)} total, showing first 30):")
            for ip in ip_addresses[:30]:
                lines.append(f"- {ip}")
            lines.append("")
        
        # Domains (new - separated from IPs)
        domains = aggregated.get("domains", [])
        if domains:
            lines.append(f"DOMAINS ({len(domains)} total, showing first 30):")
            for domain in domains[:30]:
                lines.append(f"- {domain}")
            lines.append("")
        
        # URLs (new)
        urls = aggregated.get("urls", [])
        if urls:
            lines.append(f"URLS ({len(urls)} total, showing first 30):")
            for url in urls[:30]:
                lines.append(f"- {url}")
            lines.append("")
        
        # Network indicators (legacy - kept for backward compatibility)
        network = aggregated.get("network", [])
        if network:
            lines.append(f"NETWORK INDICATORS ({len(network)} total, showing first 30):")
            for n in network[:30]:
                lines.append(f"- {n}")
            lines.append("")
        
        # Registry keys (new)
        registry_keys = aggregated.get("registry_keys", [])
        if registry_keys:
            lines.append(f"REGISTRY KEYS ({len(registry_keys)} total, showing first 30):")
            for key in registry_keys[:30]:
                lines.append(f"- {key}")
            lines.append("")
        
        # Mutexes (new)
        mutexes = aggregated.get("mutexes", [])
        if mutexes:
            lines.append(f"MUTEXES ({len(mutexes)} total, showing first 30):")
            for mutex in mutexes[:30]:
                lines.append(f"- {mutex}")
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
    
    def run(self, llm_client, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate IOC extraction using raw markdown mode.
        
        Args:
            llm_client: LLM client instance
            aggregated: Aggregated VT data
            
        Returns:
            Dict with IOC results or error info:
            - Success: {"raw_text": "...", "attempts": 1, "model": "..."}
            - Failure: {"error": "...", "raw_text": "", "attempts": 1}
        """
        llm_cfg = self.config.get("llm", {})
        ioc_model = llm_cfg.get("ioc_model") or llm_cfg.get("model", "gpt-4o-mini")
        
        # Get UI locale for language adaptation
        ui_locale = self.config.get("ui", {}).get("default_language", "en")
        locale_map = {
            "en": "English",
            "ru": "Russian",
            "kz": "Kazakh"
        }
        locale_name = locale_map.get(ui_locale, "English")
        
        # Raw mode path
        self.logger.info(f"IOC raw extraction using model={ioc_model}, locale={ui_locale}")
        
        try:
            # Build context
            context = self._build_context(aggregated)
            
            # Build prompts with locale instruction
            locale_instruction = f"\n\nIMPORTANT: The user interface language is {locale_name}. Please provide all explanatory text and descriptions in {locale_name}. However, keep technical indicators (IPs, domains, file paths, hashes, etc.) and code exactly as they are without translation."
            
            user_prompt = self.raw_user_template.replace("{CONTEXT}", context) + locale_instruction
            
            # Truncate if too long (rough estimate: 1 token ~= 4 chars)
            # Keep under 20k chars to be safe
            max_chars = 20000
            if len(user_prompt) > max_chars:
                self.logger.warning(f"User prompt too long ({len(user_prompt)} chars), truncating to {max_chars}")
                user_prompt = user_prompt[:max_chars] + "\n\n[... truncated for length ...]"
            
            # Add locale context to system prompt as well
            system_prompt_with_locale = f"{self.raw_system_prompt}\n\nUser interface locale: {locale_name}. Provide explanatory text in {locale_name}, but keep technical indicators unchanged."
            
            # Combine system and user prompts for complete_once
            combined_prompt = f"{system_prompt_with_locale}\n\n{user_prompt}"
            
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
