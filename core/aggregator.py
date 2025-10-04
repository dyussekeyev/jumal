from typing import Dict, Any

class Aggregator:
    """
    Aggregates VirusTotal responses into a normalized structure.

    Expects each VT call possibly wrapped as:
      {"ok": True, "status": 200, "data": {...}}
    or {"ok": False, "status": 404/403, "error": "..."}
    or legacy raw dict.

    Pulls MITRE techniques from behaviour_mitre_trees (new)
    but still accepts legacy 'attack_techniques' key for backward compatibility.
    """

    def __init__(self, logger):
        self.logger = logger

    def _unwrap(self, node):
        if isinstance(node, dict) and node.get("ok") and "data" in node:
            return node["data"]
        return node

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

        # --- MITRE via behaviour_mitre_trees ---
        mitre_node = self._unwrap(
            vt_data.get("behaviour_mitre_trees") or
            vt_data.get("attack_techniques") or
            {}
        )

        mitre_list = []
        if isinstance(mitre_node, dict):
            # The VT endpoint typically returns { "data": [ { "attributes": {...} } ] }
            data_list = mitre_node.get("data") or []
            for t in data_list:
                attr = t.get("attributes", {}) if isinstance(t, dict) else {}
                tid = attr.get("technique_id")
                tname = attr.get("technique")
                tactic = attr.get("tactic")
                # Build readable label
                if tid:
                    label = f"{tid}"
                    if tname:
                        label += f" {tname}"
                    if tactic:
                        label += f" (tactic: {tactic})"
                    mitre_list.append(label)

        # Comments
        comments_node = self._unwrap(vt_data.get("comments", {}))
        comments_raw = []
        if isinstance(comments_node, dict):
            comments_raw = comments_node.get("data", []) or []
        comments_list = []
        for c in comments_raw[:20]:
            attr = c.get("attributes", {}) if isinstance(c, dict) else {}
            text = attr.get("text", "")
            comments_list.append(text[:300])

        # Behaviours (sandbox)
        behaviours_node = self._unwrap(
            vt_data.get("behaviour") or vt_data.get("behaviours") or {}
        )
        processes = []
        network = []
        if isinstance(behaviours_node, dict):
            data_section = behaviours_node.get("data") or behaviours_node
            if isinstance(data_section, dict):
                procs = data_section.get("processes") or []
                for p in procs[:25]:
                    if isinstance(p, dict):
                        pname = p.get("name") or p.get("command_line")
                        if pname:
                            processes.append(pname[:120])
                nets = data_section.get("network") or {}
                if isinstance(nets, dict):
                    hosts = nets.get("hosts") or []
                    for h in hosts[:25]:
                        if isinstance(h, dict):
                            ip = h.get("ip") or h.get("domain")
                            if ip:
                                network.append(ip)

        # YARA / Sigma
        yara_node = self._unwrap(
            vt_data.get("yara_ruleset") or
            vt_data.get("yara_rulesets") or
            vt_data.get("crowdsourced_yara_rulesets")
        )
        sigma_node = self._unwrap(
            vt_data.get("sigma_rules") or
            vt_data.get("crowdsourced_sigma_rules")
        )

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
            "yara_ruleset": yara_node if yara_node else None,
            "sigma_rules": sigma_node if sigma_node else None
        }
