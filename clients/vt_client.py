import time
import requests
from typing import Dict, Any, Optional, Union, Tuple

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
    VirusTotal V3 API client (focused subset).

    Notes:
      - Endpoints used:
          /files/{id}
          /files/{id}/behaviours          (plural form to fetch all behavior reports)
          /files/{id}/attack_techniques
          /files/{id}/comments
          /files/{id}/crowdsourced_yara_rulesets
          /files/{id}/crowdsourced_sigma_rules
      - Rate limiting:
          Enforces a minimum interval (min_interval) between *any* requests.
          On 429: sleeps a fixed 15s (configurable via on_rate_limit_sleep()).
      - Retries:
          Applied only to transient conditions: 429, 5xx, network exceptions, JSON parse errors.
          Does NOT retry 400/401/403/404 (except you may choose to treat 404 as final).
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

    # ---------------------- Internal Utilities ----------------------

    def _rate_limit_sleep(self):
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.min_interval:
            wait = self.min_interval - elapsed
            self.logger.debug(f"[VT] Sleeping {wait:.2f}s to respect min_interval.")
            time.sleep(wait)

    def _sleep_backoff(self, attempt: int):
        delay = self.backoff_base * (2 ** (attempt - 1))
        self.logger.debug(f"[VT] Backoff sleep {delay:.2f}s (attempt {attempt}).")
        time.sleep(delay)

    def _handle_429(self, attempt: int):
        self.logger.warning(f"[VT] 429 rate limit encountered. Sleeping {self.RATE_LIMIT_SLEEP_ON_429}s.")
        time.sleep(self.RATE_LIMIT_SLEEP_ON_429)
        if attempt >= self.max_retries:
            raise VTRateLimitError("Exceeded max retries after repeated 429 responses.")

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

            # Success
            if status == 200:
                try:
                    data = resp.json()
                    return {"ok": True, "status": status, "data": data}
                except ValueError as e:
                    self.logger.error(f"[VT] JSON decode error: {e}")
                    if attempt >= self.max_retries:
                        raise VTClientError("Invalid JSON after max retries") from e
                    self._sleep_backoff(attempt)
                    continue

            # Not found
            if status == 404:
                self.logger.info(f"[VT] Not found: {url}")
                return {"ok": False, "status": status, "error": "not_found"}

            # Auth / permission
            if status in (400, 401, 403):
                msg = f"Client/authorization error {status}: {resp.text[:200]}"
                self.logger.error(f"[VT] {msg}")
                if status in (401, 403):
                    raise VTAuthError(msg)
                raise VTClientError(msg)

            # Rate limit
            if status == 429:
                if attempt >= self.max_retries:
                    raise VTRateLimitError("Max retries on 429.")
                self._handle_429(attempt)
                continue

            # Server errors
            if 500 <= status < 600:
                self.logger.warning(f"[VT] Server error {status}. Body: {resp.text[:200]}")
                if attempt >= self.max_retries:
                    raise VTServerError(f"Server error {status} after retries.")
                self._sleep_backoff(attempt)
                continue

            # Unexpected
            self.logger.error(f"[VT] Unexpected status {status}. Body: {resp.text[:200]}")
            raise VTUnexpectedStatus(f"Unexpected status {status}")

    # ---------------------- Public Methods ----------------------

    def get_file_report(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}")

    def get_behaviours(self, h: str) -> Dict[str, Any]:
        # Using plural form as per docs for all sandbox behaviour reports.
        return self._request("GET", f"/files/{h}/behaviours")

    def get_attack_techniques(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}/attack_techniques")

    def get_comments(self, h: str, limit: int = 20) -> Dict[str, Any]:
        limit = max(1, min(limit, 40))  # enforce a reasonable cap
        return self._request("GET", f"/files/{h}/comments", params={"limit": limit})

    def get_crowdsourced_yara_rulesets(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}/crowdsourced_yara_rulesets")

    def get_crowdsourced_sigma_rules(self, h: str) -> Dict[str, Any]:
        return self._request("GET", f"/files/{h}/crowdsourced_sigma_rules")
