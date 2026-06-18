"""A thin, polite HTTP client wrapper around requests.

Centralizes session reuse, timeouts, a custom User-Agent, optional rate
limiting and basic retry handling so the scanner modules stay simple.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

DEFAULT_UA = "WVS/0.1 (Web Vulnerability Scanner; authorized testing only)"


def _extract_set_cookie(resp) -> list:
    """Return each individual Set-Cookie header value (requests merges them in .headers)."""
    try:
        values = resp.raw.headers.getlist("Set-Cookie")
        if values:
            return list(values)
    except Exception:
        pass
    single = resp.headers.get("Set-Cookie")
    return [single] if single else []


@dataclass
class Response:
    """A simplified, normalized response object."""

    url: str
    status_code: int
    headers: dict
    text: str
    elapsed: float
    ok: bool
    set_cookie: list = field(default_factory=list)  # individual Set-Cookie header values


class HttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.0,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = True,
        max_retries: int = 0,
        workers: int = 8,
    ) -> None:
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.workers = max(1, workers)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = verify_tls
        # Size the connection pool for the worker count so concurrent requests
        # don't exhaust it.
        adapter = HTTPAdapter(
            pool_connections=self.workers, pool_maxsize=max(self.workers, 10)
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self._last_request_ts = 0.0
        self._throttle_lock = threading.Lock()

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._throttle_lock:
            elapsed = time.monotonic() - self._last_request_ts
            wait = self.delay - elapsed
            if wait > 0:
                time.sleep(wait)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        allow_redirects: bool = True,
        headers: Optional[dict] = None,
    ) -> Optional[Response]:
        """Perform a request, returning a normalized Response or None on failure."""
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                resp = self.session.request(
                    method.upper(),
                    url,
                    params=params,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    headers=headers,
                )
                self._last_request_ts = time.monotonic()
                return Response(
                    url=resp.url,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    elapsed=resp.elapsed.total_seconds(),
                    ok=resp.ok,
                    set_cookie=_extract_set_cookie(resp),
                )
            except requests.RequestException as exc:
                last_exc = exc
                self._last_request_ts = time.monotonic()
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                continue
        # All attempts failed.
        _ = last_exc
        return None

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None,
            **kwargs) -> Optional[Response]:
        return self.request("GET", url, params=params, headers=headers, **kwargs)

    def post(self, url: str, data: Optional[dict] = None, headers: Optional[dict] = None,
             **kwargs) -> Optional[Response]:
        return self.request("POST", url, data=data, headers=headers, **kwargs)

    def get_many(self, urls: list, allow_redirects: bool = True,
                 headers: Optional[dict] = None, deadline_s: Optional[float] = None) -> list:
        """GET many URLs, returning Responses in the same order as ``urls``.

        Runs concurrently with up to ``self.workers`` threads. ``deadline_s``
        bounds the total wall-clock: URLs not fetched in time get ``None`` (so a
        slow/blocking target can't make a path-probe module run for minutes).
        Falls back to a sequential pass when a delay is configured (politeness)
        or only one worker is allowed.
        """
        if not urls:
            return []
        if self.workers <= 1 or self.delay > 0:
            results, start = [], time.monotonic()
            for u in urls:
                if deadline_s is not None and time.monotonic() - start > deadline_s:
                    break
                results.append(self.get(u, allow_redirects=allow_redirects, headers=headers))
            results.extend([None] * (len(urls) - len(results)))
            return results

        results: list = [None] * len(urls)
        pool = ThreadPoolExecutor(max_workers=self.workers)
        futures = {
            pool.submit(self.get, u, allow_redirects=allow_redirects, headers=headers): i
            for i, u in enumerate(urls)
        }
        try:
            for fut in as_completed(futures, timeout=deadline_s):
                results[futures[fut]] = fut.result()
        except FuturesTimeout:
            pass  # deadline hit; unfetched URLs stay None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return results

    def close(self) -> None:
        self.session.close()
