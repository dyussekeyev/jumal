import json
import re
from typing import Dict, Any, Optional, Tuple, List

# Regex to find JSON blocks
JSON_BLOCK_RE = re.compile(r"\{.*?\}", re.DOTALL)


class IOCExtractor:
    """
    Builds IOC extraction prompt and parses structured IOC JSON from LLM response.
    
    Second LLM pass dedicated to extracting Indicators of Compromise (IOCs)
    and YARA/Sigma rules from aggregated VT behavior data.
    """
    
    def __init__(self, logger):
        self.logger = logger
    
    def build_ioc_prompt(self, aggregated: Dict[str, Any]) -> str:
        """
        Build a concise prompt for IOC extraction.
        
        Args:
            aggregated: Aggregated VT data structure
            
        Returns:
            Prompt string for LLM
        """
        lines = []
        lines.append("TASK: Extract structured Indicators of Compromise (IOCs) from the following malware analysis data.")
        lines.append("")
        lines.append("INSTRUCTIONS:")
        lines.append("- Return ONLY a valid JSON object (no other text)")
        lines.append("- Extract unique values only")
        lines.append("- Limit each array to max 100 items")
        lines.append("- Use empty arrays [] for missing data")
        lines.append("")
        
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
        
        # Output schema
        lines.append("OUTPUT: Return a JSON object with this exact structure:")
        lines.append("{")
        lines.append('  "process_names": [],        // Unique process/executable names')
        lines.append('  "network_ips": [],          // IP addresses only')
        lines.append('  "network_domains": [],      // Domain names (exclude IPs)')
        lines.append('  "urls": [],                 // Full URLs with protocol')
        lines.append('  "file_paths": [],           // File system paths')
        lines.append('  "registry_keys": [],        // Registry keys/paths')
        lines.append('  "mutexes": [],              // Mutex names')
        lines.append('  "yara_rules": [],           // YARA rule names')
        lines.append('  "sigma_rules": [],          // Sigma rule names/titles')
        lines.append('  "other_iocs": []            // Any other indicators')
        lines.append("}")
        lines.append("")
        lines.append("Extract relevant indicators from the data above. Use heuristics:")
        lines.append("- IPs: strings with digits and dots (e.g., 192.168.1.1)")
        lines.append("- Domains: strings with dots and letters (exclude IPs)")
        lines.append("- URLs: strings containing ://")
        lines.append("- Process names: extract from PROCESSES section")
        lines.append("- Ensure all arrays contain unique values")
        
        return "\n".join(lines)
    
    def parse_ioc_json(self, full_text: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Parse IOC JSON from LLM response.
        
        Args:
            full_text: Full LLM response text
            
        Returns:
            Tuple of (parsed_json_dict or None, error_message)
        """
        match = JSON_BLOCK_RE.search(full_text)
        if not match:
            msg = "No JSON block found in IOC extraction response"
            self.logger.warning(msg)
            return None, msg
        
        candidate = match.group(0)
        try:
            parsed = json.loads(candidate)
            
            # Validate structure - ensure all required keys exist
            required_keys = [
                "process_names", "network_ips", "network_domains", "urls",
                "file_paths", "registry_keys", "mutexes", 
                "yara_rules", "sigma_rules", "other_iocs"
            ]
            
            for key in required_keys:
                if key not in parsed:
                    parsed[key] = []
                # Ensure each value is a list
                if not isinstance(parsed[key], list):
                    parsed[key] = []
            
            # Enforce uniqueness and limits
            for key in required_keys:
                if isinstance(parsed[key], list):
                    # Make unique while preserving order
                    unique_items = []
                    seen = set()
                    for item in parsed[key][:100]:  # Max 100 items
                        item_str = str(item).strip()
                        if item_str and item_str not in seen:
                            unique_items.append(item_str)
                            seen.add(item_str)
                    parsed[key] = unique_items
            
            return parsed, ""
            
        except json.JSONDecodeError as e:
            msg = f"IOC JSON parse failed: {e}"
            self.logger.warning(msg)
            return None, msg
        except Exception as e:
            msg = f"Unexpected error parsing IOC JSON: {e}"
            self.logger.exception(msg)
            return None, msg
    
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
