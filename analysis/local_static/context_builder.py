import json
import re
import logging
from typing import Dict, Any, List, Optional

from core.config import LOCALE_NAMES
from .models import FileAnalysisPipelineResult, StaticAnalysisResult, VTFileStatus


_SUSPICIOUS_STRING_PATTERNS = [
    r"http[s]?://",
    r"cmd\.exe",
    r"powershell",
    r"wscript",
    r"cscript",
    r"HKEY_",
    r"HKLM\\",
    r"HKCU\\",
    r"CreateProcess",
    r"VirtualAlloc",
    r"WriteProcessMemory",
    r"GetProcAddress",
    r"LoadLibrary",
    r"base64",
    r"WinExec",
    r"ShellExecute",
    r"RegSetValue",
]


def _compact_strings(strings: List[str], max_count: int = 50) -> List[str]:
    """Return the *max_count* most suspicious strings from *strings*."""
    if not strings:
        return []
    scored = []
    for s in strings:
        score = sum(
            1 for p in _SUSPICIOUS_STRING_PATTERNS if re.search(p, s, re.IGNORECASE)
        )
        scored.append((score, s))
    scored.sort(key=lambda x: -x[0])
    return [s for _, s in scored[:max_count]]


class CombinedContextBuilder:
    """
    Builds a combined LLM prompt from VirusTotal data and local static analysis.

    VT context ordering is preserved (same as the existing Summarizer.build_prompt).
    Local static analysis is appended after the VT block.
    """

    MAX_YARA_HITS = 20
    MAX_CAPA_CAPS = 30
    MAX_STRINGS = 50
    MAX_STACK_STRINGS = 20

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # VT section (mirrors Summarizer.build_prompt ordering exactly)
    # ------------------------------------------------------------------
    def _build_vt_lines(self, vt_aggregated: Dict[str, Any]) -> List[str]:
        lines: List[str] = []
        b = vt_aggregated.get("basic", {})
        lines.append("FILE SUMMARY:")
        lines.append(f"Detections: {b.get('detections')}")
        lines.append(f"Type: {b.get('type_description')}")
        lines.append(f"Size: {b.get('size')}")
        lines.append(f"Names: {', '.join(b.get('names', []))}")
        lines.append("")
        lines.append("MITRE TECHNIQUES:")
        for t in vt_aggregated.get("mitre", []):
            lines.append(f"- {t}")
        lines.append("")
        lines.append("PROCESSES:")
        for p in vt_aggregated.get("processes", []):
            lines.append(f"- {p}")
        lines.append("")
        lines.append("NETWORK:")
        for n in vt_aggregated.get("network", []):
            lines.append(f"- {n}")
        lines.append("")
        lines.append("COMMENTS (up to 20):")
        for c in vt_aggregated.get("comments", [])[:20]:
            lines.append(f"- {c}")
        lines.append("")
        lines.append("YARA (if any):")
        if vt_aggregated.get("yara_ruleset"):
            lines.append(json.dumps(vt_aggregated["yara_ruleset"])[:1000])
        else:
            lines.append("None")
        lines.append("")
        lines.append("SIGMA (if any):")
        if vt_aggregated.get("sigma_rules"):
            lines.append(json.dumps(vt_aggregated["sigma_rules"])[:1000])
        else:
            lines.append("None")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Local static analysis section
    # ------------------------------------------------------------------
    def _build_static_lines(self, static: StaticAnalysisResult) -> List[str]:
        lines: List[str] = ["LOCAL STATIC ANALYSIS:", ""]

        sample = static.sample
        hashes = sample.get("hashes", {})
        lines.append(f"File: {sample.get('file_name', 'unknown')}")
        lines.append(f"Size: {sample.get('file_size', 'unknown')} bytes")
        for algo in ("md5", "sha1", "sha256"):
            if hashes.get(algo):
                lines.append(f"{algo.upper()}: {hashes[algo]}")
        lines.append("")

        # File type
        die = static.file_type.get("die", {})
        if die:
            lines.append(
                f"Detected type (DIE): {die.get('format_detail') or die.get('raw') or 'N/A'}"
            )
            lines.append(f"Format family: {die.get('format_family', 'unknown')}")
            lines.append("")

        generic = static.generic_analysis

        # YARA hits
        yara_matches = generic.get("yara", {}).get("matches", [])
        if yara_matches:
            lines.append(f"LOCAL YARA HITS ({len(yara_matches)}):")
            for m in yara_matches[: self.MAX_YARA_HITS]:
                if isinstance(m, dict):
                    rule = m.get("rule") or m.get("name", "unknown")
                    tags = m.get("tags", [])
                    tag_str = f" [{', '.join(tags)}]" if tags else ""
                    lines.append(f"- {rule}{tag_str}")
                else:
                    lines.append(f"- {m}")
            lines.append("")

        # FLOSS strings (compacted)
        floss = generic.get("floss", {})
        static_strs = floss.get("static_strings", [])
        if static_strs:
            top = _compact_strings(static_strs, self.MAX_STRINGS)
            if top:
                lines.append(
                    f"SUSPICIOUS STRINGS (top {len(top)} of {len(static_strs)} static):"
                )
                for s in top:
                    lines.append(f"  {str(s)[:120]}")
                lines.append("")

        stack_strs = floss.get("stack_strings", [])
        if stack_strs:
            show = stack_strs[: self.MAX_STACK_STRINGS]
            lines.append(
                f"STACK STRINGS ({len(stack_strs)} found, showing {len(show)}):"
            )
            for s in show:
                lines.append(f"  {str(s)[:120]}")
            lines.append("")

        decoded_strs = floss.get("decoded_strings", [])
        if decoded_strs:
            show = decoded_strs[: self.MAX_STACK_STRINGS]
            lines.append(f"DECODED STRINGS ({len(decoded_strs)} found, showing {len(show)}):")
            for s in show:
                lines.append(f"  {str(s)[:120]}")
            lines.append("")

        # Specialized
        specialized = static.specialized_analysis

        capa = specialized.get("capa")
        if capa and isinstance(capa, dict) and not capa.get("error"):
            caps = capa.get("capabilities", [])
            attack = capa.get("attack", [])
            if caps or attack:
                lines.append(f"CAPA CAPABILITIES ({len(caps)} total):")
                for c in caps[: self.MAX_CAPA_CAPS]:
                    if isinstance(c, dict):
                        ns = c.get("namespace", "")
                        ns_str = f" [{ns}]" if ns else ""
                        lines.append(f"- {c.get('name', 'unknown')}{ns_str}")
                    else:
                        lines.append(f"- {c}")
                if attack:
                    lines.append("CAPA ATT&CK:")
                    for t in attack[:20]:
                        if isinstance(t, dict):
                            lines.append(
                                f"- {t.get('technique_id', '')} {t.get('technique', '')}".strip()
                            )
                lines.append("")

        office = specialized.get("office")
        if office and isinstance(office, dict) and not office.get("error"):
            lines.append("OFFICE DOCUMENT ANALYSIS:")
            mraptor = office.get("mraptor", {})
            if mraptor:
                lines.append(f"  Mraptor verdict: {mraptor.get('verdict', 'unknown')}")
            olevba = office.get("olevba", {})
            if olevba:
                lines.append(f"  Macros: {olevba.get('macro_count', 0)}")
                kws = olevba.get("suspicious_keywords", [])
                if kws:
                    lines.append(f"  Suspicious keywords: {', '.join(kws[:20])}")
            oledump = office.get("oledump", {})
            if oledump:
                macro_streams = [
                    s for s in oledump.get("streams", [])
                    if isinstance(s, dict) and s.get("has_macro")
                ]
                if macro_streams:
                    lines.append(f"  OLE streams with macros: {len(macro_streams)}")
            lines.append("")

        pdf = specialized.get("pdf")
        if pdf and isinstance(pdf, dict) and not pdf.get("error"):
            lines.append("PDF DOCUMENT ANALYSIS:")
            pdfid = pdf.get("pdfid", {})
            if pdfid:
                suspicious = pdfid.get("suspicious", [])
                if suspicious:
                    lines.append(f"  Suspicious indicators: {', '.join(suspicious)}")
                for kw, count in list(pdfid.get("keywords", {}).items())[:10]:
                    if count > 0:
                        lines.append(f"  {kw}: {count}")
            lines.append("")

        # Tool warnings
        failed = [tr for tr in static.tool_runs if tr.status in ("error", "timeout")]
        if static.errors or failed:
            lines.append("TOOL WARNINGS:")
            for e in static.errors[:5]:
                lines.append(f"  [!] {e}")
            for tr in failed:
                suffix = f" – {tr.error}" if tr.error else ""
                lines.append(f"  [!] {tr.tool}: {tr.status}{suffix}")
            lines.append("")

        return lines

    # ------------------------------------------------------------------
    # Indicator summary
    # ------------------------------------------------------------------
    def _build_indicator_lines(
        self,
        pipeline: FileAnalysisPipelineResult,
        vt_aggregated: Optional[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = ["INDICATOR & RULE SUMMARY:", ""]

        static = pipeline.local_static

        # Local YARA
        if static:
            yara_matches = static.generic_analysis.get("yara", {}).get("matches", [])
            if yara_matches:
                lines.append(f"Local YARA rules matched ({len(yara_matches)}):")
                for m in yara_matches[:10]:
                    if isinstance(m, dict):
                        lines.append(
                            f"  - {m.get('rule', 'unknown')} {m.get('tags', [])}"
                        )
                    else:
                        lines.append(f"  - {m}")

        # VT YARA / Sigma
        if vt_aggregated:
            vt_yara = vt_aggregated.get("yara_ruleset") or []
            if vt_yara:
                lines.append(f"VT YARA ({len(vt_yara)} rules):")
                for r in vt_yara[:10]:
                    if isinstance(r, dict):
                        name = r.get("rule_name") or r.get("rule") or r.get("name")
                        if name:
                            lines.append(f"  - {name}")
            vt_sigma = vt_aggregated.get("sigma_rules") or []
            if vt_sigma:
                lines.append(f"VT Sigma ({len(vt_sigma)} rules):")
                for r in vt_sigma[:10]:
                    if isinstance(r, dict):
                        name = r.get("rule_name") or r.get("title") or r.get("name")
                        if name:
                            lines.append(f"  - {name}")

        # Hashes
        if static and static.sample.get("hashes"):
            h = static.sample["hashes"]
            lines.append("Hashes:")
            for algo in ("md5", "sha1", "sha256"):
                if h.get(algo):
                    lines.append(f"  {algo}: {h[algo]}")

        # VT status note
        vt_labels = {
            "ok": "Found in VirusTotal",
            "not_found": "Not found in VirusTotal (file NOT uploaded)",
            "error": "VirusTotal lookup failed",
            "rate_limited": "VirusTotal rate limited",
            "skipped": "VirusTotal not queried",
        }
        lines.append(
            f"VT Status: {vt_labels.get(pipeline.vt_status.value, pipeline.vt_status.value)}"
        )
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Full combined prompt
    # ------------------------------------------------------------------
    def build_full_prompt(
        self,
        system_prompt: str,
        pipeline: FileAnalysisPipelineResult,
        vt_aggregated: Optional[Dict[str, Any]] = None,
        locale: str = "en",
    ) -> str:
        """
        Build a complete LLM prompt merging VT data and local static analysis.

        VT ordering is preserved exactly as in Summarizer.build_prompt.
        """
        locale_name = LOCALE_NAMES.get(locale, "English")

        lines: List[str] = []

        if vt_aggregated:
            lines += self._build_vt_lines(vt_aggregated)
        else:
            vt_label = {
                "not_found": "File hash not known to VirusTotal (file NOT uploaded)",
                "error": "VirusTotal lookup failed",
                "rate_limited": "VirusTotal rate limited",
                "skipped": "VirusTotal not queried",
            }.get(pipeline.vt_status.value, pipeline.vt_status.value.upper())
            lines.append(f"VIRUSTOTAL DATA: {vt_label}")
            lines.append("")

        if pipeline.local_static:
            lines += self._build_static_lines(pipeline.local_static)

        lines += self._build_indicator_lines(pipeline, vt_aggregated)

        if pipeline.pipeline_errors:
            lines.append("PIPELINE WARNINGS:")
            for e in pipeline.pipeline_errors:
                lines.append(f"- {e}")
            lines.append("")

        lines.append("TASK:")
        lines.append(
            f"User interface locale: {locale_name}. "
            f"Provide all narrative and explanatory text in {locale_name}, "
            "but keep service keys (verdict, confidence, etc.), hashes, "
            "technical indicators, and code blocks in their original form."
        )
        lines.append("")
        lines.append(
            "Return FIRST a strict JSON object with fields: "
            "verdict (malicious|suspicious|benign|unknown), "
            "confidence (0-100 integer), "
            "key_capabilities (list of short strings), "
            "mitre_techniques (list of technique IDs like T1059), "
            "recommended_actions (list), "
            "raw_summary (short technical paragraph)."
        )
        lines.append(
            f"Then after the JSON, provide a detailed free-text analysis in {locale_name}."
        )

        user_prompt = "\n".join(lines)
        system_with_locale = (
            f"{system_prompt}\n\n"
            f"User interface locale: {locale_name}. "
            f"Generate main analysis text in {locale_name}."
        )
        return f"{system_with_locale}\n\n{user_prompt}"
