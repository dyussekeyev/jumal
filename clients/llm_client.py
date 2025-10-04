import requests
import json
from typing import Generator, Dict, Any

class LLMClient:
    """
    Minimal OpenAI-compatible streaming client (chat/completions).
    """
    def __init__(self, base_url: str, api_key: str, model: str, stream_enabled: bool, timeout: int, logger):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.stream_enabled = stream_enabled
        self.timeout = timeout
        self.logger = logger

    def stream_chat(self, prompt: str) -> Generator[str, None, None]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "stream": self.stream_enabled
        }
        if self.stream_enabled:
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=self.timeout) as r:
                r.raise_for_status()
                for line in r.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data = line[6:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            obj = json.loads(data)
                            # OpenAI style: choices[].delta.content
                            choices = obj.get("choices", [])
                            for c in choices:
                                delta = c.get("delta", {})
                                content = delta.get("content")
                                if content:
                                    yield content
                        except Exception:
                            self.logger.debug(f"Non-JSON line: {line[:100]}")
        else:
            # Non-stream fallback
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            yield content