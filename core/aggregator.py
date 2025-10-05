from typing import Dict, Any, List
import re

class Aggregator:
    """
    Aggregates VirusTotal responses into normalized structure.

    MITRE: из behaviour_mitre_trees
    YARA/Sigma: из поведения (crowdsourced_yara_results / crowdsourced_sigma_results)
    """

    def __init__(self, logger):
        self.logger = logger

    def _unwrap(self, node):
        if isinstance(node, dict) and node.get("ok") and "data" in node:
            return node["data"]
        return node

    def _extract_mitre(self, mitre_node) -> List[str]:
        out = []
        if isinstance(mitre_node, dict):
            data_list = mitre_node.get("data") or []
            for t in data_list:
                if not isinstance(t, dict):
                    continue
                attr = t.get("attributes", {})
                tid = attr.get("technique_id")
                tname = attr.get("technique")
                tactic = attr.get("tactic")
                if tid:
                    label = tid
                    if tname:
                        label += f" {tname}"
                    if tactic:
                        label += f" (tactic: {tactic})"
                    out.append(label)
        return out

    def _extract_yara_sigma(self, behaviours_node) -> tuple[Any, Any]:
        """
        Возвращает (yara_results, sigma_results).
        Формат VT может быть:
          behaviours_node.data.crowdsourced_yara_results
          behaviours_node.data.attributes.crowdsourced_yara_results
          (то же для sigma)
        Берём сырые списки (ограничим по длине).
        """
        candidates = []
        if isinstance(behaviours_node, dict):
            candidates.append(behaviours_node.get("data"))
            if isinstance(behaviours_node.get("data"), dict):
                candidates.append(behaviours_node["data"].get("attributes"))
            # fallback: сам behaviours_node (если структура иная)
            candidates.append(behaviours_node)

        yara_res = None
        sigma_res = None

        for c in candidates:
            if not isinstance(c, dict):
                continue
            if yara_res is None and "crowdsourced_yara_results" in c:
                # ограничим до 50 правил
                raw = c.get("crowdsourced_yara_results")
                if isinstance(raw, list):
                    yara_res = raw[:50]
            if sigma_res is None and "crowdsourced_sigma_results" in c:
                raw = c.get("crowdsourced_sigma_results")
                if isinstance(raw, list):
                    sigma_res = raw[:50]
            if yara_res and sigma_res:
                break

        return yara_res, sigma_res

    def _extract_ips(self, text: str) -> List[str]:
        """Extract IPv4 addresses from text."""
        # IPv4 pattern
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ipv4_pattern, text)
        # Basic validation - ensure each octet is 0-255
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                valid_ips.append(ip)
        return valid_ips

    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text (exclude pure IP addresses)."""
        # Simple domain pattern: word.word or word.word.word etc.
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        # Filter out things that look like IPs
        return [d for d in domains if not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', d)]

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        # Match http:// or https:// URLs
        url_pattern = r'https?://[A-Za-z0-9._:%\-/?#=&+]+'
        urls = re.findall(url_pattern, text)
        # Clean trailing punctuation
        cleaned = []
        for url in urls:
            url = url.rstrip('.,;:)]}>')
            if url:
                cleaned.append(url)
        return cleaned

    def _extract_file_paths(self, text: str) -> List[str]:
        """Extract Windows file paths from text."""
        paths = []
        # Windows drive paths: C:\... or D:\... etc.
        drive_pattern = r'[A-Za-z]:\\[^\s"\'<>|]*'
        paths.extend(re.findall(drive_pattern, text))
        # UNC paths: \\server\share\...
        unc_pattern = r'\\\\[^\s"\'<>|]+'
        paths.extend(re.findall(unc_pattern, text))
        # Clean up - remove trailing punctuation
        cleaned = []
        for path in paths:
            path = path.rstrip('.,;:)]}>')
            if path:
                cleaned.append(path)
        return cleaned

    def _extract_registry_keys(self, text: str) -> List[str]:
        """Extract Windows registry keys from text."""
        # Match registry key patterns
        reg_patterns = [
            r'HKEY_[A-Z_]+\\[^\s"\'<>|]+',
            r'HKLM\\[^\s"\'<>|]+',
            r'HKCU\\[^\s"\'<>|]+',
            r'HKCR\\[^\s"\'<>|]+',
            r'HKU\\[^\s"\'<>|]+',
            r'HKCC\\[^\s"\'<>|]+',
            r'\\REGISTRY\\[^\s"\'<>|]+'
        ]
        keys = []
        for pattern in reg_patterns:
            keys.extend(re.findall(pattern, text, re.IGNORECASE))
        # Clean trailing punctuation
        cleaned = []
        for key in keys:
            key = key.rstrip('.,;:)]}>')
            if key:
                cleaned.append(key)
        return cleaned

    def _deduplicate_preserve_case(self, items: List[str]) -> List[str]:
        """Deduplicate list case-insensitively but preserve original casing."""
        seen = {}
        result = []
        for item in items:
            lower = item.lower()
            if lower not in seen:
                seen[lower] = True
                result.append(item)
        return result

    def _extract_file_name_from_path(self, path: str) -> str:
        """Extract filename from a file path."""
        # Handle both forward and back slashes
        if '\\' in path:
            return path.split('\\')[-1]
        elif '/' in path:
            return path.split('/')[-1]
        return path

    def build_struct(self, vt_data: Dict[str, Any]) -> Dict[str, Any]:
        file_report = self._unwrap(vt_data.get("file_report", {})) or {}
        attributes = {}
        if isinstance(file_report.get("data"), dict):
            attributes = file_report["data"].get("attributes", {})
        elif "attributes" in file_report:
            attributes = file_report.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0) or 0
        suspicious = stats.get("suspicious", 0) or 0
        detections = malicious + suspicious

        size = attributes.get("size")
        md5 = attributes.get("md5")
        sha256 = attributes.get("sha256")
        type_description = attributes.get("type_description")
        names = attributes.get("names", [])[:10]

        mitre_node = self._unwrap(
            vt_data.get("behaviour_mitre_trees") or
            vt_data.get("attack_techniques") or {}
        )
        mitre_list = self._extract_mitre(mitre_node)

        comments_node = self._unwrap(vt_data.get("comments", {}))
        comments_raw = []
        if isinstance(comments_node, dict):
            comments_raw = comments_node.get("data", []) or []
        comments_list = []
        for c in comments_raw[:20]:
            if isinstance(c, dict):
                attr = c.get("attributes", {})
                text = attr.get("text", "")
                comments_list.append(text[:300])

        behaviours_node = self._unwrap(
            vt_data.get("behaviour") or vt_data.get("behaviours") or {}
        )
        processes = []
        network = []
        
        # New IOC collections
        all_file_paths = []
        all_registry_keys = []
        all_mutexes = []
        all_urls = []
        all_ips = []
        all_domains = []
        
        if isinstance(behaviours_node, dict):
            data_section = behaviours_node.get("data") or behaviours_node
            
            # Handle case where data is a list of sandbox reports
            sandbox_reports = []
            if isinstance(data_section, list):
                sandbox_reports = data_section
            elif isinstance(data_section, dict):
                # Single sandbox report or dict format
                sandbox_reports = [data_section]
            
            # Process each sandbox report
            for sandbox_data in sandbox_reports[:5]:  # Limit to first 5 sandboxes
                if not isinstance(sandbox_data, dict):
                    continue
                
                # Get attributes if this is a VT API response format
                attrs = sandbox_data.get("attributes") or sandbox_data
                if not isinstance(attrs, dict):
                    continue
                
                # Extract processes and command lines
                procs = attrs.get("processes") or []
                for p in procs[:25]:
                    if isinstance(p, dict):
                        # Prefer command_line over name for better context
                        pname = p.get("command_line") or p.get("name")
                        if pname:
                            processes.append(pname[:120])
                            # Extract file paths from command lines
                            all_file_paths.extend(self._extract_file_paths(pname))
                
                # Also check processes_created (alternative field name)
                procs_created = attrs.get("processes_created") or []
                for pc in procs_created[:25]:
                    if isinstance(pc, str):
                        processes.append(pc[:120])
                        all_file_paths.extend(self._extract_file_paths(pc))
                    elif isinstance(pc, dict):
                        pname = pc.get("command_line") or pc.get("name")
                        if pname:
                            processes.append(pname[:120])
                            all_file_paths.extend(self._extract_file_paths(pname))

                # Extract mutexes
                mutexes = attrs.get("mutexes_created") or []
                if isinstance(mutexes, list):
                    all_mutexes.extend(mutexes[:40])

                # Extract registry keys
                reg_keys_opened = attrs.get("registry_keys_opened") or []
                if isinstance(reg_keys_opened, list):
                    all_registry_keys.extend(reg_keys_opened[:40])
                
                reg_keys_set = attrs.get("registry_keys_set") or []
                if isinstance(reg_keys_set, list):
                    for reg_item in reg_keys_set[:40]:
                        if isinstance(reg_item, dict):
                            key = reg_item.get("key")
                            if key:
                                all_registry_keys.append(key)
                        elif isinstance(reg_item, str):
                            all_registry_keys.append(reg_item)

                # Extract network indicators
                nets = attrs.get("network") or {}
                if isinstance(nets, dict):
                    hosts = nets.get("hosts") or []
                    for h in hosts[:25]:
                        if isinstance(h, dict):
                            ip = h.get("ip")
                            domain = h.get("domain")
                            if ip:
                                network.append(ip)
                                all_ips.append(ip)
                            if domain and not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
                                network.append(domain)
                                all_domains.append(domain)
                    
                    # Extract URLs from http_conversations or dns_requests
                    http_convs = nets.get("http_conversations") or []
                    for conv in http_convs:
                        if isinstance(conv, dict):
                            url = conv.get("url")
                            if url:
                                all_urls.append(url)
                    
                    dns_reqs = nets.get("dns_requests") or []
                    for dns in dns_reqs:
                        if isinstance(dns, dict):
                            hostname = dns.get("hostname")
                            if hostname and not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
                                all_domains.append(hostname)

        # Extract IOCs from Sigma analysis results
        yara_results, sigma_results = self._extract_yara_sigma(behaviours_node)
        
        if sigma_results and isinstance(sigma_results, list):
            for sigma_rule in sigma_results[:50]:
                if not isinstance(sigma_rule, dict):
                    continue
                match_contexts = sigma_rule.get("match_context") or []
                for ctx in match_contexts:
                    if not isinstance(ctx, dict):
                        continue
                    values = ctx.get("values") or {}
                    if not isinstance(values, dict):
                        continue
                    
                    # Extract file paths from various fields
                    for field in ["Image", "ParentImage", "TargetFilename", "CurrentDirectory"]:
                        val = values.get(field)
                        if val and isinstance(val, str):
                            all_file_paths.extend(self._extract_file_paths(val))
                    
                    # Extract from command lines
                    for field in ["CommandLine", "ParentCommandLine"]:
                        val = values.get(field)
                        if val and isinstance(val, str):
                            all_file_paths.extend(self._extract_file_paths(val))
                            all_urls.extend(self._extract_urls(val))
                            all_registry_keys.extend(self._extract_registry_keys(val))

        # Deduplicate and cap each category
        CAP = 40
        
        file_paths = self._deduplicate_preserve_case(all_file_paths)[:CAP]
        registry_keys = self._deduplicate_preserve_case(all_registry_keys)[:CAP]
        mutexes = self._deduplicate_preserve_case(all_mutexes)[:CAP]
        urls = self._deduplicate_preserve_case(all_urls)[:CAP]
        ip_addresses = self._deduplicate_preserve_case(all_ips)[:CAP]
        domains = self._deduplicate_preserve_case(all_domains)[:CAP]
        
        # Extract file names from VT attributes.names + basenames of file paths
        file_name_set = []
        # From VT names
        for name in names:
            if name:
                file_name_set.append(name)
        # From extracted file paths
        for path in file_paths:
            fname = self._extract_file_name_from_path(path)
            if fname and fname not in file_name_set:
                file_name_set.append(fname)
        # From process names
        for proc in processes:
            fname = self._extract_file_name_from_path(proc)
            if fname and fname not in file_name_set:
                file_name_set.append(fname)
        
        file_names = self._deduplicate_preserve_case(file_name_set)[:CAP]

        return {
            "basic": {
                "detections": detections,
                "malicious": malicious,
                "suspicious": suspicious,
                "size": size,
                "md5": md5,
                "sha256": sha256,
                "type_description": type_description,
                "names": names
            },
            "mitre": mitre_list,
            "comments": comments_list,
            "processes": processes,
            "network": network,
            # Сохраняем старые ключи для Summarizer:
            "yara_ruleset": yara_results,
            "sigma_rules": sigma_results,
            # New IOC categories
            "file_paths": file_paths,
            "registry_keys": registry_keys,
            "mutexes": mutexes,
            "urls": urls,
            "ip_addresses": ip_addresses,
            "domains": domains,
            "file_names": file_names
        }

