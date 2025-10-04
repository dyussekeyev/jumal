import requests
import json
from typing import Generator, Optional

class LLMClientError(Exception):
    """Generic LLM client error."""

class LLMAuthError(LLMClientError):
    """Authentication / authorization error (401/403)."""

class LLMBadRequestError(LLMClientError):
    """Invalid request parameters / model not found (400 / 404)."""

class LLMServerError(LLMClientError):
    """Server side / transient errors (5xx)."""

class LLMClient:
    """
    OpenAI-compatible (and optionally Ollama) streaming client.

    Supports:
      - POST /v1/chat/completions (OpenAI style)
      - POST /api/chat          (Ollama heuristic if base_url points to localhost:11434)

    Streaming yields incremental text chunks.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        stream_enabled: bool,
        timeout: int,
        logger
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = (api_key or "").strip()
        self.model = model
        self.stream_enabled = stream_enabled
        self.timeout = timeout
        self.logger = logger

        # Heuristic: Ollama typical local endpoint
        self._is_ollama = (
            "localhost:11434" in self.base_url
            or "127.0.0.1:11434" in self.base_url
        )

        if not self._is_ollama and not self.api_key:
            # Remote provider without key → fail fast
            raise LLMAuthError("LLM API key is empty (remote provider). Set llm.api_key in config.json.")

    # ---------- Public ----------

    def stream_chat(self, prompt: str) -> Generator[str, None, None]:
        """
        Streams model output. Raises:
          LLMAuthError, LLMBadRequestError, LLMServerError, LLMClientError
        """
        if self._is_ollama:
            yield from self._stream_ollama(prompt)
        else:
            yield from self._stream_openai(prompt)
    
    def complete_once(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.0
    ) -> str:
        """
        Non-streaming completion for structured extraction.
        
        Args:
            prompt: The prompt to send
            model: Optional model override (default: use self.model)
            temperature: Temperature setting (default: 0.0 for deterministic)
            
        Returns:
            Full completion text
            
        Raises:
            LLMAuthError, LLMBadRequestError, LLMServerError, LLMClientError
        """
        use_model = model or self.model
        
        if self._is_ollama:
            return self._complete_once_ollama(prompt, use_model, temperature)
        else:
            return self._complete_once_openai(prompt, use_model, temperature)

    # ---------- OpenAI style ----------

    def _stream_openai(self, prompt: str) -> Generator[str, None, None]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "stream": self.stream_enabled
        }

        if self.stream_enabled:
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=self.timeout) as r:
                if r.status_code != 200:
                    self._raise_http_error(r)
                for line in r.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data = line[6:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            obj = json.loads(data)
                        except Exception:
                            continue
                        for c in obj.get("choices", []):
                            delta = c.get("delta", {})
                            content = delta.get("content")
                            if content:
                                yield content
        else:
            r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            if r.status_code != 200:
                self._raise_http_error(r)
            data = r.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if content:
                yield content

    # ---------- Ollama ----------

    def _stream_ollama(self, prompt: str) -> Generator[str, None, None]:
        url = f"{self.base_url}/api/chat"
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": self.stream_enabled
        }

        with requests.post(url, headers=headers, json=payload, stream=True, timeout=self.timeout) as r:
            if r.status_code != 200:
                self._raise_http_error(r)
            if not self.stream_enabled:
                data = r.json()
                msg = data.get("message", {})
                content = msg.get("content", "")
                if content:
                    yield content
                return
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                msg = obj.get("message") or {}
                content = msg.get("content")
                if content:
                    yield content
                if obj.get("done"):
                    break

    # ---------- Error handling ----------

    def _raise_http_error(self, response: requests.Response):
        status = response.status_code
        text = (response.text or "").strip()
        preview = text[:400]
        self.logger.error(f"[LLM] HTTP {status}: {preview}")
        if status in (401, 403):
            raise LLMAuthError(f"LLM authorization failed ({status}). Body: {preview}")
        if status in (400, 404):
            raise LLMBadRequestError(f"LLM bad request ({status}). Body: {preview}")
        if 500 <= status < 600:
            raise LLMServerError(f"LLM server error ({status}). Body: {preview}")
        raise LLMClientError(f"LLM unexpected status {status}. Body: {preview}")
    
    # ---------- Non-streaming completions ----------
    
    def _complete_once_openai(
        self,
        prompt: str,
        model: str,
        temperature: float
    ) -> str:
        """Non-streaming OpenAI-compatible completion."""
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "stream": False
        }
        
        r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        if r.status_code != 200:
            self._raise_http_error(r)
        
        data = r.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return content
    
    def _complete_once_ollama(
        self,
        prompt: str,
        model: str,
        temperature: float
    ) -> str:
        """Non-streaming Ollama completion."""
        url = f"{self.base_url}/api/chat"
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        
        r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        if r.status_code != 200:
            self._raise_http_error(r)
        
        data = r.json()
        content = data.get("message", {}).get("content", "")
        return content
