# JUMAL – Junior Malware Analyst

AI-assisted triage tool for malware samples.  
Queries VirusTotal by hash or analyzes local files with Docker-based static tools, then runs an LLM to summarize capabilities, indicators, and recommended actions.

> **Disclaimer:** AI assessments are not guaranteed to be accurate. Always corroborate results with professional malware analysis workflows.

---

## Table of Contents

1. [What it does](#what-it-does)
2. [Prerequisites](#prerequisites)
3. [Quick start (local run)](#quick-start-local-run)
4. [Docker run (Ollama local LLM)](#docker-run-ollama-local-llm)
5. [Configuration](#configuration)
6. [Tabs overview](#tabs-overview)
7. [Troubleshooting](#troubleshooting)

---

## What it does

- **Hash-based VT lookup** – enter an MD5, SHA1, or SHA256 hash to retrieve file report, sandbox behaviour, MITRE ATT&CK techniques, comments, and crowdsourced YARA/Sigma rules from VirusTotal.
- **Local file analysis** – select a file (up to 100 MB); the tool computes hashes locally, queries VT by hash only (never uploads the file), then runs Docker-based static analysis tools (diec, yara, floss, capa, oletools, pdfid).
- **Dual LLM analysis** – first pass streams a verdict and summary; second pass extracts structured IOCs in 11 categories.
- **Multilingual UI** – English, Russian, Kazakh (configured in `config.json`).
- **Report saving** – JSON bundle + plain-text export from both analysis modes.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.11+ | `python --version` |
| VirusTotal API key | Free tier works; rate limits apply |
| LLM access | OpenRouter, OpenAI, or local Ollama (see below) |
| Docker (optional) | Required only for Docker-based static analysis |

---

## Quick start (local run)

```bash
# 1. Clone and enter the repo
git clone https://github.com/dyussekeyev/jumal.git
cd jumal

# 2. Create and activate a virtual environment
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your config (copy the template, then edit)
cp config.json.template config.json
# Open config.json in any text editor and fill in:
#   virustotal.api_key   – your VirusTotal API key
#   llm.api_key          – your LLM API key (leave empty for local Ollama)
#   llm.provider_url     – LLM endpoint (default: OpenRouter)
#   llm.model            – model name

# 5. Run
python main.py
```

---

## Docker run (Ollama local LLM)

Use this to run Ollama locally so JUMAL can work without a cloud LLM account.

### Start Ollama

Run from the **repository root** (where `compose.yaml` lives):

```bash
docker compose up -d
```

> ⚠ **Common mistake:** running `docker compose up` from `docker/analyzer/` or `ollama/`  
> will produce `no configuration file provided: not found`.  
> Always run from the repository root.

This starts the `jumal-ollama` container, which:
- Exposes the Ollama API on `http://localhost:11434`
- Pulls `llama3.2:1b` automatically on first start (≈700 MB download)

### Configure JUMAL to use Ollama

In `config.json` set:

```json
{
  "llm": {
    "provider_url": "http://localhost:11434",
    "api_key": "",
    "model": "llama3.2:1b"
  }
}
```

### Static analyzer Docker image

The static analyzer (`docker/analyzer/`) is **not** a long-running service. JUMAL builds and runs it automatically on demand the first time you analyze a file. No manual `docker build` is required.

---

## Configuration

Edit `config.json` in a text editor. The file is created from `config.json.template` on first run if it does not exist.

Key sections:

| Section | Field | Description |
|---------|-------|-------------|
| `virustotal` | `api_key` | VirusTotal API key |
| `virustotal` | `base_url` | VT API base URL (default: `https://www.virustotal.com/api/v3`) |
| `virustotal` | `min_interval_seconds` | Minimum seconds between VT requests (default: `15`) |
| `llm` | `provider_url` | LLM endpoint URL |
| `llm` | `api_key` | LLM API key (empty for local Ollama) |
| `llm` | `model` | Model name (e.g. `meta-llama/llama-3.2-1b-instruct`) |
| `llm` | `ioc_model` | Separate model for IOC extraction (optional; uses `model` if empty) |
| `ui` | `default_language` | UI language: `en`, `ru`, or `kz` |
| `output` | `directory` | Report output directory (default: `reports/`) |
| `network` | `request_timeout_seconds` | HTTP request timeout |

---

## Tabs overview

| Tab | Contents |
|-----|----------|
| **File Analysis** | Local file pipeline: hashes, VT lookup, Docker static tools, LLM summary. Copy Summary and Save Report buttons. |
| **VT-only Analysis** | Hash-based VT lookup + LLM streaming summary. Copy Summary and Save Report buttons. |
| **Indicators/Rules** | AI-extracted IOCs from the most recent analysis (11 categories: file names, processes, IPs, domains, URLs, file paths, registry keys, mutexes, YARA, Sigma, other). |
| **Raw** | Raw JSON output from VT API or the file analysis pipeline. |

---

## Troubleshooting

### `no configuration file provided: not found`

You ran `docker compose` from the wrong directory.  
Always run from the **repository root**:

```bash
cd /path/to/jumal
docker compose up -d
```

### Ollama model not pulling

If the container starts but the model download fails, pull manually:

```bash
docker exec jumal-ollama ollama pull llama3.2:1b
```

### VirusTotal 401 / auth errors

Check that `virustotal.api_key` in `config.json` is correct. Free-tier keys have rate limits; increase `min_interval_seconds` if you see 429 errors.

### LLM auth error

Verify `llm.api_key` and `llm.provider_url` in `config.json`. For Ollama, `api_key` must be empty and `provider_url` must point to `http://localhost:11434`.

### Docker not available – static analysis skipped

Ensure Docker Desktop (Windows/macOS) or Docker Engine (Linux) is running. JUMAL will still perform VT lookup and LLM analysis without Docker; only the local static tool results will be missing.

### Config file not found on startup

Copy the template and fill in your API keys:

```bash
cp config.json.template config.json
```
