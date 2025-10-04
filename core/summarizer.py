import json
import re
from typing import Dict, Any

JSON_BLOCK_RE = re.compile(r"\{.*?\}", re.DOTALL)

class Summarizer:
    def __init__(self, logger):
        self.logger = logger

    def build_prompt(self, system_prompt: str, aggregated: Dict[str, Any]) -> str:
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
        lines.append("Return FIRST a strict JSON object with fields: verdict (malicious|suspicious|benign|unknown), confidence (0-100 integer), key_capabilities (list of short strings), mitre_techniques (list of technique IDs like T1059), recommended_actions (list), raw_summary (short technical paragraph).")
        lines.append("Then after the JSON, provide a detailed free-text analysis in the same language of input (English).")
        user_prompt = "\n".join(lines)
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        return full_prompt

    def extract_json_and_text(self, full_response: str):
        # naive extraction: find first balanced looking JSON
        match = JSON_BLOCK_RE.search(full_response)
        parsed = None
        json_text = None
        free_text = full_response
        if match:
            candidate = match.group(0)
            try:
                parsed = json.loads(candidate)
                json_text = candidate
                free_text = full_response.replace(candidate, "").strip()
            except Exception as e:
                self.logger.warning(f"JSON parse failed: {e}")
        return parsed, free_text