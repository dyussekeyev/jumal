from typing import Dict, Any

class Aggregator:
    """
    Aggregates raw VirusTotal responses into a normalized structure for prompt building and report saving.
    """
    def __init__(self, logger):
        self.logger = logger

    def build_struct(self, vt_data: Dict[str, Any]) -> Dict[str, Any]:
        # vt_data expected keys: file_report, behaviour, attack_techniques, comments, yara_ruleset, sigma_rules
        file_report = vt_data.get("file_report", {}) or {}
        attributes = file_report.get("data", {}).get("attributes", {}) if isinstance(file_report.get("data"), dict) else {}
        stats = attributes.get("last_analysis_stats", {})
        detections = sum(v for k, v in stats.items() if k not in ("harmless", "timeout", "undetected", "type-unsupported"))
        size = attributes.get("size")
        md5 = attributes.get("md5")
        sha256 = attributes.get("sha256")
        type_description = attributes.get("type_description")
        names = attributes.get("names", [])[:10]

        mitre = vt_data.get("attack_techniques", {}).get("data", []) if vt_data.get("attack_techniques") else []
        mitre_list = []
        for t in mitre:
            attr = t.get("attributes", {})
            tid = attr.get("technique_id")
            if tid:
                name = attr.get("technique")
                mitre_list.append(f"{tid} {name}" if name else tid)

        comments_raw = vt_data.get("comments", {}).get("data", []) if vt_data.get("comments") else []
        comments_list = []
        for c in comments_raw[:20]:
            attr = c.get("attributes", {})
            text = attr.get("text", "")
            comments_list.append(text[:300])

        behaviour = vt_data.get("behaviour", {})
        processes = []
        network = []
        if isinstance(behaviour, dict):
            # heuristic extraction
            data = behaviour.get("data") or behaviour
            # Just a shallow example. Real extraction would parse processes, calls, etc.
            if isinstance(data, dict):
                procs = data.get("processes") or []
                for p in procs[:20]:
                    if isinstance(p, dict):
                        pname = p.get("name") or p.get("command_line")
                        if pname:
                            processes.append(pname[:120])
                nets = data.get("network") or {}
                if isinstance(nets, dict):
                    hosts = nets.get("hosts") or []
                    for h in hosts[:20]:
                        if isinstance(h, dict):
                            ip = h.get("ip") or h.get("domain")
                            if ip:
                                network.append(ip)

        yara_ruleset = vt_data.get("yara_ruleset") if vt_data.get("yara_ruleset") else None
        sigma_rules = vt_data.get("sigma_rules") if vt_data.get("sigma_rules") else None

        return {
            "basic": {
                "detections": detections,
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
            "yara_ruleset": yara_ruleset,
            "sigma_rules": sigma_rules
        }