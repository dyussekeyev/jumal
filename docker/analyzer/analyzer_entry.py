#!/usr/bin/env python3
"""
JUMAL Analyzer – Docker container entrypoint.

Reads /workspace/input/sample, runs static analysis tools, and writes
/workspace/output/result.json.  Always exits 0 so the host can read
partial results even when individual tools fail.
"""

import json
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

INPUT_FILE = "/workspace/input/sample"
OUTPUT_DIR = "/workspace/output"
RULES_DIR = "/workspace/rules"
RESULT_PATH = os.path.join(OUTPUT_DIR, "result.json")

# Per-tool timeouts in seconds
TIMEOUTS = {
    "diec":        30,
    "yara":        30,
    "floss":      120,
    "capa":       180,
    "mraptor":     30,
    "olevba":      60,
    "oledump":     30,
    "pdfid":       30,
    "pdf-parser":  60,
}

OLEDUMP  = "/usr/local/lib/oledump.py"
PDFID    = "/usr/local/lib/pdfid.py"
PDFPARSE = "/usr/local/lib/pdf-parser.py"


# ─────────────────────────── helpers ─────────────────────────────────────────

def _run(cmd, timeout=60):
    """
    Run *cmd* and return (stdout, stderr, returncode, elapsed_ms, error_tag).
    error_tag is None when the tool ran (even if it exited non-zero);
    otherwise "timeout", "not_found", or a string describing the exception.
    returncode is None when the tool could not be started.
    """
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode, int((time.monotonic()-t0)*1000), None
    except subprocess.TimeoutExpired:
        return "", "", None, int((time.monotonic()-t0)*1000), "timeout"
    except FileNotFoundError:
        return "", "", None, int((time.monotonic()-t0)*1000), "not_found"
    except Exception as exc:
        return "", "", None, int((time.monotonic()-t0)*1000), str(exc)


def _tool_run(tool, status, elapsed, stderr="", error=""):
    return {"tool": tool, "status": status, "duration_ms": elapsed,
            "stderr": stderr[:300], "error": error}


# ─────────────────────────── hashes ──────────────────────────────────────────

def compute_hashes(path):
    m, s1, s256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            m.update(chunk); s1.update(chunk); s256.update(chunk)
    return {"md5": m.hexdigest(), "sha1": s1.hexdigest(), "sha256": s256.hexdigest()}


# ─────────────────────────── diec ────────────────────────────────────────────

def run_diec(path):
    stdout, stderr, rc, ms, err = _run(["diec", "--json", path], TIMEOUTS["diec"])
    if err == "not_found":
        # diec binary missing in container — attempt a simple fallback using `file`
        # Keep tool_run indicating not_found, but populate some useful fallback info.
        file_out, file_err, file_rc, file_ms, file_errtag = _run(["file", "-b", path], timeout=5)
        family, detail, raw = "unknown", "", {}
        detail = (file_out.strip() if file_out else "") or ""
        dl = detail.lower()
        if "pe32" in dl or "pe" in dl or "portable" in dl:
            family = "pe"
        elif "elf" in dl:
            family = "elf"
        elif "mach-o" in dl or "mach o" in dl:
            family = "macho"
        raw = {"file_output": (file_out or "").strip()}
        tr = _tool_run("diec", "not_found", ms, error="diec not found")
        # include stdout/stderr placeholders so UI/RAW can show fallback
        info = {"raw": raw, "format_family": family, "format_detail": detail,
                "raw_stdout": stdout[:20000], "raw_stderr": stderr[:2000]}
        return info, tr

    status = "ok" if (rc == 0 and not err) else ("timeout" if err == "timeout" else "error")
    tr = _tool_run("diec", status, ms, stderr, error=err or "")

    family, detail, raw = "unknown", "", {}
    if stdout:
        try:
            data = json.loads(stdout)
            raw = data
            detects = data.get("detects", [])
            if detects:
                first = detects[0]
                ftype  = first.get("filetype", first.get("type", "")).lower()
                values = first.get("values", [])
                val_str = values[0].get("string", "") if values and isinstance(values[0], dict) else ""
                detail = val_str or first.get("string", "") or ftype
                dl     = detail.lower()
                if any(x in ftype for x in ("pe32","pe64","pe ")):  family = "pe"
                elif "elf"   in ftype or "elf"   in dl:             family = "elf"
                elif "mach-o" in ftype or "mach-o" in dl:           family = "macho"
                elif any(x in ftype for x in ("word","excel","powerpoint","office","ole","docx","xlsx","pptx","doc","xls","ppt")):
                    family = "office"
                elif "pdf" in ftype or "pdf" in dl:                 family = "pdf"
                else:
                    if   "pe32" in dl or "portable executable" in dl: family = "pe"
                    elif "elf"  in dl:                                family = "elf"
                    elif "mach-o" in dl:                              family = "macho"
                    elif any(x in dl for x in ("word","excel","office","ole")): family = "office"
                    elif "pdf" in dl:                                 family = "pdf"
        except (ValueError, KeyError):
            detail = stdout.strip()
            dl = detail.lower()
            if   "pe32" in dl or "pe64" in dl:  family = "pe"
            elif "elf"  in dl:                  family = "elf"
            elif "mach-o" in dl:                family = "macho"

    # ensure raw stdout/stderr are included for debugging (truncate to reasonable size)
    info = {"raw": raw, "format_family": family, "format_detail": detail,
            "raw_stdout": stdout[:20000], "raw_stderr": stderr[:2000]}
    return info, tr


# ─────────────────────────── yara ────────────────────────────────────────────

def run_yara(path, rules_dir):
    rule_files = [
        str(p) for p in Path(rules_dir).rglob("*")
        if p.suffix in (".yar", ".yara", ".rules") and p.is_file()
    ]
    if not rule_files:
        return {"matches": [], "rules_count": 0, "raw_stdout": "", "raw_stderr": ""}, \
               _tool_run("yara", "skipped", 0, error="no rules found")

    matches, total_ms = [], 0
    last_err = None
    combined_stdout = []
    combined_stderr = []
    for rf in rule_files[:10]:
        out, err_txt, rc, ms, err = _run(["yara", "-r", rf, path], TIMEOUTS["yara"])
        total_ms += ms
        if err == "not_found":
            return {"matches": [], "rules_count": 0, "raw_stdout": "", "raw_stderr": ""}, \
                   _tool_run("yara", "not_found", total_ms, error="yara not found")
        last_err = err
        combined_stdout.append(out or "")
        combined_stderr.append(err_txt or "")
        if rc == 0 and out:
            for line in out.strip().splitlines():
                line = line.strip()
                if line:
                    parts = line.split(" ", 1)
                    matches.append({"rule": parts[0],
                                    "matched_file": parts[1] if len(parts)>1 else path})

    status = "timeout" if last_err == "timeout" else ("error" if last_err else "ok")
    return {"matches": matches, "rules_count": len(rule_files),
            "raw_stdout": "\n".join(combined_stdout)[:20000],
            "raw_stderr": "\n".join(combined_stderr)[:2000]}, \
           _tool_run("yara", status, total_ms)


# ─────────────────────────── floss ───────────────────────────────────────────

def run_floss(path):
    out, err_txt, rc, ms, err = _run(
        ["floss", "--no-progress", "--format", "json", path], TIMEOUTS["floss"])

    if err == "not_found":
        return {"static_strings":[], "stack_strings":[], "decoded_strings":[], "raw_stdout": "", "raw_stderr": ""}, \
               _tool_run("floss", "not_found", ms, error="floss not found")

    status = "ok" if (rc == 0 and not err) else ("timeout" if err=="timeout" else "error")
    tr = _tool_run("floss", status, ms, err_txt, error=err or "")

    res = {"static_strings":[], "stack_strings":[], "decoded_strings":[], "raw_stdout": out[:20000], "raw_stderr": err_txt[:2000]}
    if out:
        try:
            data = json.loads(out)
            strs = data.get("strings", data)  # floss >=3 nests under "strings"
            def _pick(lst):
                return [
                    (s.get("string", s) if isinstance(s, dict) else s)
                    for s in lst
                ]
            res["static_strings"]  = _pick(strs.get("static_strings",  []))[:500]
            res["stack_strings"]   = _pick(strs.get("stack_strings",   []))[:200]
            res["decoded_strings"] = _pick(strs.get("decoded_strings", []))[:200]
        except (ValueError, KeyError):
            res["static_strings"] = [l for l in out.splitlines() if len(l.strip()) >= 4][:500]
    return res, tr


# ─────────────────────────── capa ────────────────────────────────────────────

def run_capa(path):
    out, err_txt, rc, ms, err = _run(["capa", "--json", path], TIMEOUTS["capa"])
    if err == "not_found":
        return {"error":"not_found","capabilities":[],"attack":[], "raw_stdout": "", "raw_stderr": ""}, \
               _tool_run("capa","not_found",ms,error="capa not found")

    status = "ok" if (rc == 0 and not err) else ("timeout" if err=="timeout" else "error")
    tr = _tool_run("capa", status, ms, err_txt, error=err or "")

    caps, attack = [], []
    if out:
        try:
            data = json.loads(out)
            for name, rdata in data.get("rules", {}).items():
                if isinstance(rdata, dict):
                    meta = rdata.get("meta", {})
                    caps.append({"name": name,
                                 "namespace": meta.get("namespace",""),
                                 "attack": meta.get("attack",[])})
                    for att in meta.get("attack", []):
                        if isinstance(att, dict):
                            technique_val = att.get("technique")
                            if isinstance(technique_val, dict):
                                # Old capa format: technique is a dict with id/name
                                tid   = technique_val.get("id", "")
                                tname = technique_val.get("name", "")
                            else:
                                # New capa format (v7+): technique is a string, id is in att
                                tid   = att.get("id", "")
                                tname = str(technique_val) if technique_val else ""
                            if tid:
                                attack.append({"technique_id": tid, "technique": tname})
        except (ValueError, KeyError, AttributeError):
            pass
    return {"capabilities": caps[:50], "attack": attack[:30], "raw_stdout": out[:20000], "raw_stderr": err_txt[:2000]}, tr


# ─────────────────────────── office ──────────────────────────────────────────

def run_office(path):
    result, runs = {}, []

    # mraptor
    out, err_txt, rc, ms, err = _run(["mraptor", path], TIMEOUTS["mraptor"])
    status = "ok" if (not err and rc == 0) else ("timeout" if err=="timeout" else "error")
    runs.append(_tool_run("mraptor", status, ms, err_txt, error=err or ""))
    if not err:
        v_up = out.upper()
        verdict = "malicious" if "MALICIOUS" in v_up else ("suspicious" if "SUSPICIOUS" in v_up else "clean")
        result["mraptor"] = {"verdict": verdict, "raw": out[:500]}

    # olevba
    out, err_txt, rc, ms, err = _run(["olevba", "--json", path], TIMEOUTS["olevba"])
    status = "ok" if (not err and rc == 0) else ("timeout" if err=="timeout" else "error")
    runs.append(_tool_run("olevba", status, ms, err_txt, error=err or ""))
    if not err and out:
        try:
            data   = json.loads(out)
            macros = data.get("macros", [])
            kws    = []
            for m in macros:
                for k in m.get("suspicious_keywords", []):
                    kw = (k.get("keyword") or k.get("name","")) if isinstance(k,dict) else k
                    if kw:
                        kws.append(kw)
            result["olevba"] = {"macro_count": len(macros),
                                 "suspicious_keywords": list(dict.fromkeys(kws))[:30]}
        except (ValueError, KeyError):
            kws = [l.strip()[:100] for l in out.splitlines()
                   if "suspicious" in l.lower() or "autorun" in l.lower()]
            result["olevba"] = {"macro_count": 0, "suspicious_keywords": kws[:20]}

    # oledump
    out, err_txt, rc, ms, err = _run(
        ["python3", OLEDUMP, path], TIMEOUTS["oledump"])
    status = "ok" if (not err and rc == 0) else ("timeout" if err=="timeout" else "error")
    runs.append(_tool_run("oledump", status, ms, err_txt, error=err or ""))
    if not err and out:
        streams = [{"line": l.strip()[:200], "has_macro": "M" in l or "m" in l}
                   for l in out.strip().splitlines() if l.strip()]
        result["oledump"] = {"streams": streams[:50]}

    return result, runs


# ─────────────────────────── pdf ─────────────────────────────────────────────

def run_pdf(path):
    result, runs = {}, []
    SUSPICIOUS_PDF = {"/JS","/JavaScript","/AA","/OpenAction","/AcroForm",
                      "/JBIG2Decode","/RichMedia","/Launch","/EmbeddedFile",
                      "/XFA","/ObjStm"}

    # pdfid -j
    out, err_txt, rc, ms, err = _run(
        ["python3", PDFID, "-j", path], TIMEOUTS["pdfid"])
    status = "ok" if (not err and rc == 0) else ("timeout" if err=="timeout" else "error")
    runs.append(_tool_run("pdfid", status, ms, err_txt, error=err or ""))
    if not err and out:
        try:
            data = json.loads(out)
            kw_list = (data.get("pdfid",{})
                           .get("keywords",{})
                           .get("keyword",[]))
            keywords  = {i["name"]: i["count"] for i in kw_list
                         if isinstance(i,dict) and "name" in i}
            suspicious = [k for k,c in keywords.items()
                          if k in SUSPICIOUS_PDF and c > 0]
            result["pdfid"] = {"keywords": keywords, "suspicious": suspicious}
        except (ValueError, KeyError):
            keywords, suspicious = {}, []
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].startswith("/"):
                    try:
                        keywords[parts[0]] = int(parts[1])
                        if parts[0] in SUSPICIOUS_PDF and int(parts[1]) > 0:
                            suspicious.append(parts[0])
                    except ValueError:
                        pass
            result["pdfid"] = {"keywords": keywords, "suspicious": suspicious}

    # pdf-parser --stats
    out, err_txt, rc, ms, err = _run(
        ["python3", PDFPARSE, "--stats", path], TIMEOUTS["pdf-parser"])
    status = "ok" if (not err and rc == 0) else ("timeout" if err=="timeout" else "error")
    runs.append(_tool_run("pdf-parser", status, ms, err_txt, error=err or ""))
    if not err and out:
        result["pdf_parser"] = {"stats": out[:1000]}

    return result, runs


# ─────────────────────────── risk hints ──────────────────────────────────────

_STRING_HINTS = {
    "contains_powershell":        ["powershell","invoke-expression","iex(","encodedcommand"],
    "contains_cmd_execution":     ["cmd.exe","cmd /c","shell.run"],
    "contains_base64":            ["base64","frombase64string"],
    "contains_network_call":      ["http://","https://","socket","wininet","urldownload"],
    "contains_process_injection": ["virtualalloc","writeprocessmemory","createremotethread"],
    "contains_persistence":       ["run\\","runonce\\","startup","schtasks"],
    "packed_or_encrypted":        ["upx","packer","cipher","aes","rc4"],
}


def build_risk_hints(die_info, generic, specialized):
    hints = []
    if generic.get("yara",{}).get("matches"):
        hints.append("yara_rules_matched")

    all_strs = (generic.get("floss",{}).get("static_strings",[]) +
                generic.get("floss",{}).get("decoded_strings",[]) +
                generic.get("floss",{}).get("stack_strings",[]))
    low = [s.lower() for s in all_strs[:500] if isinstance(s,str)]
    for hint, kws in _STRING_HINTS.items():
        if any(any(k in s for k in kws) for s in low):
            hints.append(hint)

    office = specialized.get("office",{})
    if office:
        v = office.get("mraptor",{}).get("verdict","")
        if v in ("suspicious","malicious"):
            hints.append(f"office_macro_{v}")
        if office.get("olevba",{}).get("suspicious_keywords"):
            hints.append("office_macro_suspicious_keywords")

    if specialized.get("pdf",{}).get("pdfid",{}).get("suspicious"):
        hints.append("pdf_suspicious_indicators")

    capa = specialized.get("capa",{})
    if capa and not capa.get("error") and capa.get("capabilities"):
        hints.append("capa_capabilities_detected")

    return hints


# ─────────────────────────── main ────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    sample_name = os.environ.get("SAMPLE_NAME", "sample")
    path = INPUT_FILE

    if not os.path.isfile(path):
        _write({"schema_version":"1.0","errors":[f"Input not found: {path}"],
                "tool_runs":[],"sample":{},"file_type":{},"generic_analysis":{},
                "specialized_analysis":{},"risk_hints":[]})
        sys.exit(0)   # always exit 0 so host reads result.json

    tool_runs, errors = [], []
    file_size = os.path.getsize(path)

    # Hashes
    try:
        hashes = compute_hashes(path)
    except Exception as exc:
        hashes = {}
        errors.append(f"Hash computation failed: {exc}")

    # DIE
    die_info, die_tr = run_diec(path)
    tool_runs.append(die_tr)
    family = (die_info.get("format_family","unknown") if isinstance(die_info,dict)
              else "unknown")

    # YARA
    yara_res, yara_tr = run_yara(path, RULES_DIR)
    tool_runs.append(yara_tr)

    # FLOSS
    floss_res, floss_tr = run_floss(path)
    tool_runs.append(floss_tr)

    # Conditional
    specialized = {}
    if family in ("pe","elf","macho"):
        capa_res, capa_tr = run_capa(path)
        specialized["capa"] = capa_res
        tool_runs.append(capa_tr)
    elif family == "office":
        office_res, office_trs = run_office(path)
        specialized["office"] = office_res
        tool_runs.extend(office_trs)
    elif family == "pdf":
        pdf_res, pdf_trs = run_pdf(path)
        specialized["pdf"] = pdf_res
        tool_runs.extend(pdf_trs)

    generic = {"yara": yara_res, "floss": floss_res}
    risk_hints = build_risk_hints(die_info, generic, specialized)

    result = {
        "schema_version": "1.0",
        "sample":  {"file_name": sample_name, "file_size": file_size, "hashes": hashes},
        "file_type": {"die": die_info},
        "generic_analysis": generic,
        "specialized_analysis": specialized,
        "tool_runs": tool_runs,
        "risk_hints": risk_hints,
        "errors": errors,
    }
    _write(result)
    print(f"[analyzer] Complete – {len(tool_runs)} tools run, {len(errors)} errors")


def _write(data):
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
