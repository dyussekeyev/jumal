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
- Sends contextual summary to an OpenAI-compatible LLM endpoint.
- Streaming model response (first: strict JSON verdict block, then free-form analysis).
- Extracted structured fields:
  - `verdict`: malicious | suspicious | benign | unknown
  - `confidence`: 0–100
  - `key_capabilities`: list
  - `mitre_techniques`: list of technique IDs
  - `recommended_actions`: list
  - `raw_summary`: short technical paragraph
- GUI (tkinter) with tabs:
  - Summary (verdict & analysis)
  - Indicators / Rules (process artifacts, network, YARA, Sigma)
  - Raw (all JSON responses)
  - Config (edit runtime settings)
- Multilingual UI (EN / RU / KZ) via JSON resource files.
- Report saving: JSON bundle + plain text.
- Logging to file.

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
clients/
  vt_client.py       # VirusTotal API client (improved)
  llm_client.py      # OpenAI-compatible streaming client
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
3. Fetch additional endpoints (behavior, MITRE, comments, YARA, Sigma) sequentially (rate-limited).
4. Aggregate all responses into a compact structure.
5. Build LLM prompt (system prompt + structured context).
6. Stream LLM response → parse first JSON block → display structured + free text.
7. User can copy summary or save report.

---

## VirusTotal Integration Details

| Capability              | Endpoint (VT v3)                                | Notes |
|-------------------------|--------------------------------------------------|-------|
| File report             | `GET /files/{hash}`                              | Must exist before further queries |
| Behavior reports        | `GET /files/{hash}/behaviours`                   | All available sandbox behaviors |
| MITRE ATT&CK techniques | `GET /files/{hash}/attack_techniques`            | Summarized techniques |
| Comments                | `GET /files/{hash}/comments?limit=20`            | Increase with pagination later |
| YARA rulesets           | `GET /files/{hash}/crowdsourced_yara_rulesets`   | May return 404 if none |
| Sigma rules             | `GET /files/{hash}/crowdsourced_sigma_rules`     | May return 404 if none |

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

- OpenAI-compatible endpoint (defaults to `https://api.openai.com/v1`).
- Streaming supported (`stream=true`).
- Prompt structure:
  - System prompt from config.
  - User content containing detection stats, MITRE techniques, behaviors (process names, network IOCs), comments (truncated), YARA/Sigma extracts.
- Model must output:
  1. JSON block (strict object with required fields).
  2. Free-form analysis text.
- The app attempts to extract the first JSON object; if invalid, displays parsing failure message.

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
    "provider_url": "https://api.openai.com/v1",
    "api_key": "YOUR_LLM_KEY",
    "model": "gpt-4o-mini",
    "system_prompt": "You are a malware analysis assistant...",
    "stream_enabled": true
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
    "attack_techniques": {},
    "comments": {},
    "yara_rulesets": {},
    "sigma_rules": {}
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
  "meta": {
    "generator": "JUMAL 0.1",
    "llm_model": "gpt-4o-mini",
    "vt_base_url": "https://www.virustotal.com/api/v3"
  }
}
```

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

Suggested tests:
- Hash validation (MD5/SHA1/SHA256).
- VT client error paths (mock 404, 429, 5xx).
- LLM JSON extraction (valid / malformed).
- Prompt generation snapshot tests for stability.

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
