import time
import requests
from typing import Dict, Any, Optional

class VTClientError(Exception):
    """Base VirusTotal client exception."""

class VTAuthError(VTClientError):
    """Authentication / Authorization error."""

class VTRateLimitError(VTClientError):
    """Rate limit exceeded after retries."""

class VTServerError(VTClientError):
    """Server-side error after retries."""

class VTUnexpectedStatus(VTClientError):
    """Unexpected non-success status."""

class VTClient:
    """
    VirusTotal V3 API client (subset for JUMAL).

    Endpoints used now:
      - /files/{hash}
      - /files/{hash}/behaviours
      - /files/{hash}/behaviour_mitre_trees
      - /files/{hash}/comments

    YARA / Sigma больше не дергаются отдельными запросами — их результаты парсятся из поведения.

    Backward-compatible aliases:
      - get_behaviour() -> get_behaviours()
      - get_attack_techniques() -> get_behaviour_mitre_trees()  (deprecated)
    """

    RATE_LIMIT_SLEEP_ON_429 = 15

    def __init__(
        self,
        api_key: str,
        base_url: str,
        min_interval: int,
        max_retries: int,
        backoff_base: int,
        timeout: int,
        user_agent: str,
        logger,
        session: Optional[requests.Session] = None
    ):
        if not api_key:
            raise ValueError("VirusTotal API key must not be empty.")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.min_interval = max(0, min_interval)
        self.max_retries = max(1, max_retries)
        self.backoff_base = max(1, backoff_base)
        self.timeout = timeout
        self.user_agent = user_agent or "JUMAL/0.1"
        self.logger = logger
        self._last_request_ts = 0.0

        self.session = session or requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent
        })

    # ---------------- Internal ----------------

    def _rate_limit_sleep(self):
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.min_interval:
            wait = self.min_interval - elapsed
            self.logger.debug(f"[VT] Sleeping {wait:.2f}s (min interval).")
            time.sleep(wait)

    def _sleep_backoff(self, attempt: int):
        delay = self.backoff_base * (2 ** (attempt - 1))
        self.logger.debug(f"[VT] Backoff sleep {delay:.2f}s (attempt {attempt}).")
        time.sleep(delay)

    def _handle_429(self, attempt: int):
        if attempt >= self.max_retries:
            raise VTRateLimitError("Exceeded max retries after 429 responses.")
        self.logger.warning(f"[VT] 429 rate limited. Sleeping {self.RATE_LIMIT_SLEEP_ON_429}s.")
        time.sleep(self.RATE_LIMIT_SLEEP_ON_429)
        self._last_request_ts = time.time()

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        attempt = 0

        while True:
            attempt += 1
            self._rate_limit_sleep()
            self.logger.info(f"[VT] {method} {url} (attempt {attempt})")

            try:
                resp = self.session.request(method, url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                self.logger.error(f"[VT] Network error: {e}")
                if attempt >= self.max_retries:
                    raise VTClientError(f"Network error after retries: {e}") from e
                self._sleep_backoff(attempt)
                continue

            self._last_request_ts = time.time()
            status = resp.status_code

            if status == 200:
                try:
                    data = resp.json()
                    return {"ok": True, "status": status, "data": data}
                except ValueError as e:
                    self.logger.error(f"[VT] JSON parse error: {e}")
                    if attempt >= self.max_retries:
                        raise VTClientError("Invalid JSON after max retries") from e
                    self._sleep_backoff(attempt)
                    continue

            if status == 404:
                self.logger.info(f"[VT] Not found: {url}")
                return {"ok": False, "status": 404, "error": "not_found"}

            if status in (400, 401, 403):
                body = resp.text[:300]
                msg = f"Client/auth error {status}: {body}"
                self.logger.error(f"[VT] {msg}")
                if status in (401, 403):
                    raise VTAuthError(msg)
                raise VTClientError(msg)

            if status == 429:
                self._handle_429(attempt)
                continue

            if 500 <= status < 600:
                self.logger.warning(f"[VT] Server error {status}: {resp.text[:200]}")
                if attempt >= self.max_retries:
                    raise VTServerError(f"Server error {status} after retries.")
                self._sleep_backoff(attempt)
                continue

            body_preview = resp.text[:300]
            self.logger.error(f"[VT] Unexpected status {status}: {body_preview}")
            raise VTUnexpectedStatus(f"Unexpected status {status}: {body_preview}")

    # ---------------- Public API ----------------

    def get_file_report(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}")

    def get_behaviours(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}/behaviours")

    def get_behaviour_mitre_trees(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}/behaviour_mitre_trees")

    def get_comments(self, h: str, limit: int = 20) -> Dict[str, Any]:
        limit = max(1, min(limit, 40))
        return self._request("GET", f"/files/{h}/comments", params={"limit": limit})

    # ---------------- Backward-Compatible Aliases ----------------

    def get_behaviour(self, h: str) -> Dict[str, Any]:
        return self.get_behaviours(h)

    def get_attack_techniques(self, h: str) -> Dict[str, Any]:
        self.logger.debug("[VT] get_attack_techniques() deprecated → behaviour_mitre_trees")
        return self.get_behaviour_mitre_trees(h)
