# JUMAL (Junior Malware Analyst)

AI-assisted triage tool for malware samples by hash.  
It queries VirusTotal for static, behavioral, MITRE ATT&CK, comments, and crowdsourced YARA / Sigma intelligence, then uses an LLM to summarize malicious capabilities and recommended actions.

> Disclaimer: This tool provides an AI-assisted assessment and does not guarantee accuracy. Always corroborate results with professional malware analysis workflows.

---

## Key Features (MVP)

- Input a file hash (MD5 / SHA1 / SHA256) and retrieve:
  - File (static) report
  - Behavior (sandbox) reports (all available)
  - MITRE ATT&CK techniques summary
  - Comments (latest N)
  - Crowdsourced YARA rulesets (if available)
  - Crowdsourced Sigma rules (if available)
- Aggregates the above into a normalized structure.
- **Dual LLM Analysis**:
  - **First LLM pass**: Streaming analysis with verdict, confidence, capabilities, and recommendations
  - **Second LLM pass**: Non-streaming IOC extraction for structured indicators
- Extracted structured fields (first LLM):
  - `verdict`: malicious | suspicious | benign | unknown
  - `confidence`: 0–100
  - `key_capabilities`: list
  - `mitre_techniques`: list of technique IDs
  - `recommended_actions`: list
  - `raw_summary`: short technical paragraph
- Extracted IOC output (second LLM):
  - Markdown-formatted sections with indicators organized by type
  - Sections: Processes, Network IPs, Network Domains, URLs, File Paths, Registry Keys, Mutexes, YARA Rules, Sigma Rules, Other IOCs
  - Human-readable format for easy copying and analysis
  - Adapts to UI language (English, Russian, Kazakh)
- GUI (tkinter) with tabs:
  - Summary (verdict & analysis) - readonly with copy button
  - Indicators / Rules (AI-extracted IOCs, YARA, Sigma) - readonly with copy button
  - Raw (all JSON responses) - readonly with copy all button
  - Config (edit runtime settings including IOC prompts)
- Hash input enhancements: Clear, Copy, Paste buttons with clipboard integration
- Multilingual UI (EN / RU / KZ) via JSON resource files
- LLM responses adapt to active UI locale
- Report saving: JSON bundle + plain text
- Logging to file

---

## Architecture Overview

```
main.py
core/
  config.py          # Load/save JSON configuration
  logging.py         # Logging setup
  hashutil.py        # Hash validation & type detection
  aggregator.py      # Normalize VT responses
  summarizer.py      # Build LLM prompt & parse response
  ioc_extractor.py   # Build IOC extraction prompt & parse structured IOCs
clients/
  vt_client.py       # VirusTotal API client (improved)
  llm_client.py      # OpenAI-compatible streaming + non-streaming client
ui/
  app.py             # tkinter application & UI logic
i18n/
  en.json, ru.json, kz.json
reports/             # Generated reports (runtime)
logs/                # Log output (runtime)
config.json          # User configuration
```

### Data Flow

1. User enters a hash → validation (length + hex).
2. Query VirusTotal (file existence first).
3. Fetch additional endpoints (behavior, MITRE, comments) sequentially (rate-limited).
4. Aggregate all responses into a compact structure.
5. **First LLM pass**: Build main analysis prompt → stream LLM response → parse JSON verdict block → display.
6. **Second LLM pass**: Build IOC extraction prompt → non-streaming LLM call → parse structured IOC JSON.
7. Populate Indicators/Rules tab with structured IOCs.
8. User can copy summary or save report (includes both analysis and IOC summary).

---

## VirusTotal Endpoints Used

| Data Type                  | Endpoint                                            | Notes |
|--------------------------- |-----------------------------------------------------|-------|
| File report                | `/files/{hash}`                                     | Mandatory |
| Behaviour (sandbox)        | `/files/{hash}/behaviours`                          | Optional (may require higher tier) |
| MITRE ATT&CK summary       | `/files/{hash}/behaviour_mitre_trees`               | Correct endpoint (replaces deprecated `attack_techniques`) |
| Comments                   | `/files/{hash}/comments?limit=20`                   | Latest N comments |

**Note**: YARA and Sigma rules are extracted from behaviour responses (`crowdsourced_yara_results`, `crowdsourced_sigma_results`) rather than separate endpoint calls.

### Rate Limiting

- Config parameter `min_interval_seconds` ensures at most 1 request every N seconds (e.g. 15).
- On HTTP 429, an additional fixed sleep (default 15s) then retry (max attempts configured).
- Retries also applied to transient 5xx and JSON decode errors.

### Error Handling

- 404 → handled gracefully (object missing).
- 400 / 401 / 403 → non-retried, raised immediately (invalid request or permissions).
- 429 → special rate limit handling.
- 5xx → exponential backoff with base `retry_backoff_base`.

---

## LLM Integration

JUMAL uses a **dual LLM approach** for comprehensive malware analysis:

### First LLM Pass: Main Analysis (Streaming)

- OpenAI-compatible endpoint (defaults to `https://openrouter.ai/api/v1`).
- Streaming enabled for real-time feedback (`stream=true`).
- Prompt structure:
  - System prompt from config.
  - User content containing detection stats, MITRE techniques, behaviors (process names, network IOCs), comments (truncated), YARA/Sigma extracts.
- Model outputs:
  1. JSON block (strict object with required fields: verdict, confidence, capabilities, etc.).
  2. Free-form analysis text.
- The app attempts to extract the first JSON object; if invalid, displays parsing failure message.

### Second LLM Pass: IOC Extraction

IOC extraction uses **raw markdown mode**, which delegates all formatting to the LLM without local JSON parsing.

- **Raw markdown output**: LLM produces human-readable sections (Processes, Network IPs, Domains, URLs, File Paths, Registry Keys, Mutexes, YARA Rules, Sigma Rules, Other IOCs).
- **No parsing/validation**: Output is displayed verbatim in the Indicators/Rules tab with a copy button.
- **Single-pass extraction**: No retry logic, simpler error handling.
- **Configurable prompts**: Customize via `llm.ioc_raw_system_prompt` and `llm.ioc_raw_user_template` in config.
- **Model configuration**: Optional separate model via `llm.ioc_model` (fallback to main model if not set).
- **Multilingual support**: IOC extraction adapts to the active UI locale, providing explanations in the user's language while preserving technical indicators.

**Benefits**:
- Eliminates parsing errors when LLM doesn't follow strict JSON schema.
- Provides better UX with readable markdown output.
- Simplifies codebase by removing complex parsing/retry/normalization logic.
- Gives LLM full control over formatting, making it more flexible and reliable.

---

## Configuration (`config.json`)

Example:
```json
{
  "virustotal": {
    "api_key": "YOUR_VT_KEY",
    "base_url": "https://www.virustotal.com/api/v3",
    "min_interval_seconds": 15,
    "max_retries": 3,
    "retry_backoff_base": 5
  },
  "llm": {
    "provider_url": "https://openrouter.ai/api/v1",
    "api_key": "YOUR_LLM_KEY",
    "model": "meta-llama/llama-3.2-1b-instruct",
    "system_prompt": "You are a malware analysis assistant...",
    "stream_enabled": true,
    "ioc_model": null,
    "ioc_raw_system_prompt": "You are a DFIR assistant specializing in malware analysis...",
    "ioc_raw_user_template": "Based on the following malware behavior data, extract and organize all Indicators of Compromise...\n\n{CONTEXT}\n\n..."
  },
  "ui": {
    "default_language": "en"
  },
  "network": {
    "request_timeout_seconds": 30,
    "user_agent": "JUMAL/0.1"
  },
  "output": {
    "directory": "reports"
  },
  "logging": {
    "level": "INFO",
    "file": "logs/app.log"
  }
}
```

Edit key fields inside the UI Config tab or manually in file.

**Configuration Notes**:
- **GUI Editable Fields**: The following fields can now be edited directly in the GUI Config tab: `virustotal.base_url`, `llm.provider_url`, and `llm.model`. Changes are saved to `config.json` and take effect immediately after clicking Apply.
- `llm.ioc_model`: Optional. If set to `null` or omitted, the main `llm.model` is used for IOC extraction. You can specify a different model (e.g., a faster/cheaper model) for the non-streaming IOC extraction pass.
- `llm.stream_enabled`: Applies only to the first LLM pass (main analysis). IOC extraction is always non-streaming.
- `llm.ioc_raw_system_prompt`: System prompt for IOC extraction. Customize to adjust behavior.
- `llm.ioc_raw_user_template`: Template for IOC extraction prompt. Use `{CONTEXT}` placeholder for aggregated data.
- `ui.default_language`: Set UI language (en/ru/kz). The LLM will adapt its responses to match the selected language.

---

## Installation & Run

```bash
python -m venv venv
source venv/bin/activate            # On Windows: venv\Scripts\activate
pip install -r requirements.txt
# Insert your API keys into config.json
python main.py
```

---

## Report Format

`report_<hash>_<timestamp>.json`:
```json
{
  "hash": "...",
  "timestamp_utc": "...",
  "vt_raw": {
    "file_report": {},
    "behaviours": {},
    "behaviour_mitre_trees": {},
    "comments": {}
  },
  "summary": {
    "verdict": "malicious",
    "confidence": 90,
    "key_capabilities": ["persistence", "credential theft"],
    "mitre_techniques": ["T1059"],
    "recommended_actions": ["Isolate host", "Reset credentials"],
    "raw_summary": "Short paragraph",
    "free_text": "Extended analysis..."
  },
  "ioc_summary": {
    "raw_text": "## Processes\n- cmd.exe\n- powershell.exe\n\n## Network IPs\n- 192.168.1.1\n- 10.0.0.1\n\n## Network Domains\n- evil.com\n- malware.net\n\n## URLs\n- http://evil.com/payload\n\n## File Paths\n- C:\\temp\\malware.exe\n\n## Registry Keys\n- HKLM\\Software\\Malware\n\n## Mutexes\n- Global\\MalwareMutex\n\n## YARA Rules\n- MalwareRule1\n- MalwareRule2\n\n## Sigma Rules\n- SuspiciousCommand\n\n## Other IOCs\n- PDB path: ...",
    "attempts": 1,
    "model": "gpt-4o-mini"
  },
  "meta": {
    "generator": "JUMAL 0.1",
    "llm_model": "meta-llama/llama-3.2-1b-instruct",
    "ioc_model": null,
    "vt_base_url": "https://www.virustotal.com/api/v3"
  }
}
```

**Note**: If IOC extraction fails, `ioc_summary` contains an `error` field with details.

A plain text `.txt` version is also saved containing the raw streamed summary.

---

## Internationalization

Language resource files: `i18n/en.json`, `i18n/ru.json`, `i18n/kz.json`.  
To add a new language:
1. Copy `en.json` → `de.json`
2. Translate values.
3. Set `"ui.default_language": "de"` in config or pick it via GUI.

---

## Security Considerations

- API keys stored in plain text in `config.json`. Restrict file permissions if necessary.
- No sandboxing or execution of samples — hash-based intelligence only.
- LLM prompt may contain third-party comments; consider redacting if privacy is a concern.

---

## Limitations (MVP)

- No pagination beyond initial comments limit.
- Simplistic behavior extraction (process/network) — does not deeply parse all sandbox artifacts.
- No caching layer (every request hits the API).
- No CLI mode (GUI only).
- JSON parsing of LLM response is heuristic (first `{ ... }` block).
- No advanced theming (single style).
- No TLS certificate pinning or proxy support (yet).

---

## Potential Future Enhancements

- Add caching (SQLite) to reduce API calls.
- Pagination & enrichment (e.g. auto-pull full comment history).
- Deeper sandbox artifact modeling (file system, registry, dropped files).
- Additional intel sources (Hybrid Analysis, Malshare, URLhaus).
- CLI interface & batch mode.
- Configurable truncation/normalization of long comments.
- Token budgeting & prompt size guards.
- Dark/light theme toggling.

---

## Testing

Available tests:
- Hash validation (MD5/SHA1/SHA256) - `tests/test_hash_validation.py`
- LLM JSON extraction - `tests/test_llm_json_parse.py`
- Prompt generation - `tests/test_prompt_generation.py`
- **IOC extraction prompt & parsing** - `tests/test_ioc_extractor.py`

Run tests:
```bash
cd /home/runner/work/jumal/jumal
PYTHONPATH=. python tests/test_ioc_extractor.py
PYTHONPATH=. python tests/test_llm_json_parse.py
PYTHONPATH=. python tests/test_prompt_generation.py
```

Suggested additional tests:
- VT client error paths (mock 404, 429, 5xx).
- Prompt generation snapshot tests for stability.
- IOC extraction with various edge cases.

Run tests (if using pytest):
```bash
pytest
```

---

## License

MIT (see `LICENSE` file).

---

## Disclaimer

Use responsibly and in accordance with VirusTotal Terms of Service. AI outputs may include inaccuracies; always validate critical findings manually.
