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
  - Sections: **File Names**, Processes, Network IPs, Network Domains, URLs, File Paths, Registry Keys, Mutexes, YARA Rules, Sigma Rules, Other IOCs
  - Human-readable format for easy copying and analysis
  - Adapts to UI language (English, Russian, Kazakh)
  - **Enhanced extraction**: Automatically harvests IOCs from Sigma rule match contexts, process command lines, registry operations, and network artifacts
  - **Separate categories**: IPs, Domains, and URLs are now extracted and listed separately for better organization
  - **File names vs paths**: Distinguishes between filenames (e.g., "malware.exe") and full paths (e.g., "C:\\Windows\\Temp\\malware.exe")
  - **Registry keys**: Extracts registry keys from sandbox data and Sigma contexts
  - **Mutexes**: Identifies mutex creation artifacts when present in behavior data
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

- **Raw markdown output**: LLM produces human-readable sections with enhanced IOC categories:
  - **File Names**: Distinct filenames extracted from VT attributes and file paths
  - **Processes**: Process names and command lines
  - **Network IPs**: IPv4/IPv6 addresses (separated from domains)
  - **Network Domains**: Domain names only (excluding IPs)
  - **URLs**: Full HTTP/HTTPS URLs
  - **File Paths**: Complete Windows paths (drive and UNC paths)
  - **Registry Keys**: Windows registry keys from sandbox and Sigma data
  - **Mutexes**: Mutex creation artifacts
  - **YARA Rules**: Detected YARA signatures
  - **Sigma Rules**: Matched Sigma detection rules
  - **Other IOCs**: Hashes, PDB paths, imphashes, and other uncategorized indicators
- **Intelligent extraction**: Automatically harvests IOCs from:
  - Process command lines and file paths
  - Sigma rule match contexts (Image, CommandLine, TargetFilename, etc.)
  - Registry operations (keys opened/set)
  - Network artifacts (hosts, DNS requests, HTTP conversations)
  - Mutex creation events
- **Deduplication**: Case-insensitive deduplication within each category (preserves original casing)
- **Capped output**: Each category limited to 40 items to maintain prompt efficiency
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
- **Richer IOC coverage**: Extracts more indicators from deeper analysis of VT data structures.

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
- **GUI Editable Fields**: The following fields can now be edited directly in the GUI Config tab: `virustotal.base_url`, `llm.provider_url`, and `llm.model`. Changes are saved to `config.json` an[...]
- `llm.ioc_model`: Optional. If omitted or set to `null`/empty, the application automatically sets `ioc_model` to the value of `model` upon load/save. This ensures the effective model is always e[...]
- `llm.stream_enabled`: Applies only to the first LLM pass (main analysis). IOC extraction is always non-streaming.
- `llm.ioc_raw_system_prompt`: System prompt for IOC extraction. Customize to adjust behavior.
- `llm.ioc_raw_user_template`: Template for IOC extraction prompt. Use `{CONTEXT}` placeholder for aggregated data.
- `ui.default_language`: Set UI language (en/ru/kz). The LLM will adapt its responses to match the selected language.
- **Legacy Flag Removed**: The `ioc_raw_mode` flag has been removed. Raw markdown IOC extraction is now always enabled (previously controlled by this flag).

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

## Local LLM (Ollama)

You can run a local lightweight model (e.g. `llama3.2:1b`) via [Ollama](https://ollama.com/) to perform analysis without sending data to external LLM providers.

### 1. Contents

Directory `ollama/` contains:
- `Dockerfile` — builds an image with the model pre-pulled.
- `docker-compose.yml` — runs the Ollama server and pulls the model on startup.

### 2. Quick Start (Compose)

```bash
cd ollama
docker compose up -d
# or: docker-compose up -d (older Docker versions)
```

Port `11434` will be exposed locally.

### 3. (Optional) Pre-build Image

If you prefer the model to be already cached in the image:

```bash
cd ollama
docker build -t jumal-ollama .
docker run -d --name ollama -p 11434:11434 jumal-ollama
```

### 4. Pull Model Manually (If Needed)

Inside a running container or host (if native install):

```bash
ollama pull llama3.2:1b
```

### 5. Configure JUMAL to Use Local Model

Adjust `config.json`:

```json
"llm": {
  "provider_url": "http://localhost:11434",
  "api_key": "",
  "model": "llama3.2:1b",
  "system_prompt": "...",
  "stream_enabled": true,
  "ioc_model": null,
  "ioc_raw_system_prompt": "...",
  "ioc_raw_user_template": "..."
}
```

Notes:
- Ollama’s native API differs from the OpenAI Chat API. If the current LLM client expects strict OpenAI-compatible endpoints (`/v1/chat/completions`), an adapter layer may be required unless Ollama's OpenAI compatibility mode is enabled in your version.
- Model name in config must exactly match what `ollama list` shows (e.g. `llama3.2:1b`).
- Leave `api_key` empty for local use.

### 6. Testing Connectivity

A simple curl test:

```bash
curl http://localhost:11434/api/tags
```

Should return a JSON list of pulled models.

### 7. Privacy Considerations

Running locally keeps all VirusTotal-derived context on your machine (only VT API calls leave your environment). Ensure you trust any added community models.

### 8. Русская Краткая Инструкция

1. `cd ollama && docker compose up -d`  
2. Убедитесь, что порт `11434` открыт.  
3. В `config.json` установите:
   - `"provider_url": "http://localhost:11434"`
   - `"model": "llama3.2:1b"`
4. Перезапустите приложение.  
5. При необходимости вручную выполните `ollama pull llama3.2:1b`.

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
    "raw_text": "## Processes\n- cmd.exe\n- powershell.exe\n\n## Network IPs\n- 192.168.1.1\n- 10.0.0.1\n\n## Network Domains\n- evil.com\n- malware.net\n\n## URLs\n- http://evil.com/payload\n\n#[...]",
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
- Behavior extraction covers common IOC categories but may not parse all specialized sandbox artifacts.
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
