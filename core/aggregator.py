from typing import Dict, Any, List

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

        yara_results, sigma_results = self._extract_yara_sigma(behaviours_node)

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
            "sigma_rules": sigma_results
        }
