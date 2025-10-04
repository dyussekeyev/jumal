import time
import requests
from typing import Dict, Any, Optional

class VTClient:
    def __init__(self, api_key: str, base_url: str, min_interval: int, max_retries: int, backoff_base: int, timeout: int, user_agent: str, logger):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.min_interval = min_interval
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.timeout = timeout
        self.user_agent = user_agent
        self.logger = logger
        self._last_request_ts = 0
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent
        })

    def _rate_limit_sleep(self):
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.min_interval:
            wait = self.min_interval - elapsed
            self.logger.debug(f"Rate limit wait {wait:.2f}s")
            time.sleep(wait)

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        attempt = 0
        while True:
            attempt += 1
            self._rate_limit_sleep()
            self.logger.info(f"Requesting VT: {url} (attempt {attempt})")
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except Exception as e:
                self.logger.error(f"HTTP error: {e}")
                if attempt >= self.max_retries:
                    raise
                time.sleep(self.backoff_base * (2 ** (attempt - 1)))
                continue

            self._last_request_ts = time.time()

            if resp.status_code == 200:
                try:
                    return resp.json()
                except Exception as e:
                    self.logger.error(f"JSON decode error: {e}")
                    if attempt >= self.max_retries:
                        raise
                    time.sleep(self.backoff_base * (2 ** (attempt - 1)))
                    continue
            elif resp.status_code == 404:
                self.logger.info(f"Not found: {url}")
                return {"not_found": True}
            elif resp.status_code == 429:
                self.logger.warning("Rate limited (429). Sleeping 15s.")
                time.sleep(15)
                if attempt >= self.max_retries:
                    raise RuntimeError("Max retries after 429")
                continue
            elif 500 <= resp.status_code < 600:
                self.logger.warning(f"Server error {resp.status_code}")
                if attempt >= self.max_retries:
                    raise RuntimeError(f"Max retries server error {resp.status_code}")
                time.sleep(self.backoff_base * (2 ** (attempt - 1)))
                continue
            else:
                self.logger.error(f"Unexpected status {resp.status_code}: {resp.text[:200]}")
                if attempt >= self.max_retries:
                    raise RuntimeError(f"Failed with status {resp.status_code}")
                time.sleep(self.backoff_base * (2 ** (attempt - 1)))

    def get_file_report(self, h: str):
        return self._request(f"/files/{h}")

    def get_behaviour(self, h: str):
        return self._request(f"/files/{h}/behaviour")

    def get_attack_techniques(self, h: str):
        return self._request(f"/files/{h}/attack_techniques")

    def get_comments(self, h: str, limit: int = 20):
        return self._request(f"/files/{h}/comments", params={"limit": limit})

    def get_yara_ruleset(self, h: str):
        return self._request(f"/files/{h}/crowdsourced_yara_ruleset")

    def get_sigma_rules(self, h: str):
        return self._request(f"/files/{h}/crowdsourced_sigma_rules")