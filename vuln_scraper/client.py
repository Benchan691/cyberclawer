from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from .config import DEFAULT_HEADERS


class ScrapeError(Exception):
    """Base scraper exception."""


class FetchError(ScrapeError):
    """Raised when a page cannot be fetched after retries."""


class CaptchaRequiredError(FetchError):
    """Raised when a provider requires human captcha verification."""


class WAFChallengeError(FetchError):
    """Raised when a site returns a JavaScript challenge plain HTTP cannot pass."""


def looks_like_captcha_gate(html: str) -> bool:
    lowered = html.lower()
    return "data:image" in lowered and (
        "验证码" in html
        or 'type="text"' in lowered
        or "type='text'" in lowered
    )


def looks_like_waf_challenge(
    html: str,
    headers: Mapping[str, str] | None = None,
) -> bool:
    if looks_like_captcha_gate(html):
        return False

    headers = headers or {}
    punish_type = headers.get("Punish-Type") or headers.get("punish-type")
    if punish_type:
        return True

    lowered = html.lower()
    waf_markers = (
        "_waf_" in lowered,
        'id="renderdata"' in lowered or "id='renderdata'" in lowered,
        "sigchl" in lowered,
        "punish-type" in lowered,
        "__jsl_clearance" in lowered,
        "jsl_clearance" in lowered,
        "x-via-jsl" in lowered,
        "jiasule" in lowered,
        "yunaq" in lowered,
        "eo-bot-js-token" in lowered,
        "eojschallengesdk" in lowered,
        "gcaptcha.eo.gtimg.com" in lowered,
        "tencent cloud edgeone" in lowered,
    )
    return any(waf_markers) and "<table" not in lowered


class AsyncRateLimiter:
    def __init__(self, delay_seconds: float) -> None:
        self.delay_seconds = max(0.0, delay_seconds)
        self._lock = asyncio.Lock()
        self._last_request_at = 0.0

    async def wait(self) -> None:
        if self.delay_seconds <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_at
            wait_for = self.delay_seconds - elapsed
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_request_at = time.monotonic()


@dataclass(slots=True)
class FetchResult:
    html: str
    status_code: int | None
    url: str


@dataclass(slots=True)
class JSONFetchResult:
    data: Any
    status_code: int | None
    url: str


class ScraperClient:
    def __init__(
        self,
        *,
        delay: float = 1.0,
        retries: int = 3,
        backoff_base: float = 1.0,
        backoff_max: float = 30.0,
        backoff_jitter: float = 0.4,
        timeout: float = 30.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.retries = max(0, retries)
        self.backoff_base = max(0.0, backoff_base)
        self.backoff_max = max(0.0, backoff_max)
        self.backoff_jitter = max(0.0, backoff_jitter)
        self.rate_limiter = AsyncRateLimiter(delay)
        self._timeout = timeout
        self._default_headers = dict(headers or DEFAULT_HEADERS)
        self._client = self._build_http_client()

    def _build_http_client(self) -> httpx.AsyncClient:
        client_kwargs: dict[str, Any] = {
            "headers": dict(self._default_headers),
            "timeout": httpx.Timeout(self._timeout),
            "follow_redirects": True,
        }
        return httpx.AsyncClient(**client_kwargs)

    async def refresh_session(self, headers: Mapping[str, str] | None = None) -> None:
        await self._client.aclose()
        if headers is not None:
            self._default_headers = dict(headers)
        self._client = self._build_http_client()

    async def __aenter__(self) -> "ScraperClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def inject_cookies(self, cookies: list[dict[str, Any]]) -> None:
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if not name or value is None:
                continue
            self._client.cookies.set(
                name,
                value,
                domain=cookie.get("domain"),
                path=cookie.get("path") or "/",
            )

    async def get_html(
        self,
        url: str,
        *,
        retries: int | None = None,
    ) -> FetchResult:
        retry_count = self.retries if retries is None else max(0, retries)
        last_error: Exception | None = None

        for attempt in range(retry_count + 1):
            await self.rate_limiter.wait()
            try:
                response = await self._client.get(url)
                if response.status_code == 429 or response.status_code >= 500:
                    raise FetchError(f"HTTP {response.status_code} for {url}")
                response.raise_for_status()

                html = response.text
                if looks_like_waf_challenge(html, response.headers):
                    raise WAFChallengeError(
                        f"Site returned a JavaScript challenge for {url}; "
                        "a provider-specific solver is required."
                    )

                return FetchResult(
                    html=html,
                    status_code=response.status_code,
                    url=str(response.url),
                )
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, FetchError) as exc:
                last_error = exc
                if isinstance(exc, WAFChallengeError):
                    raise
                if _non_retryable_http_status(exc):
                    break
                if attempt >= retry_count:
                    break
                await self._backoff(attempt)

        raise FetchError(f"Failed to fetch {url}: {last_error}") from last_error

    async def _backoff(self, attempt: int) -> None:
        delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        jitter = random.uniform(0, self.backoff_jitter) if self.backoff_jitter > 0 else 0.0
        await asyncio.sleep(delay + jitter)

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        data: Any = None,
        retries: int | None = None,
    ) -> JSONFetchResult:
        retry_count = self.retries if retries is None else max(0, retries)
        last_error: Exception | None = None

        for attempt in range(retry_count + 1):
            await self.rate_limiter.wait()
            try:
                response = await self._client.request(
                    method.upper(),
                    url,
                    headers=dict(headers or {}),
                    json=json_body,
                    data=data,
                )
                if response.status_code == 429 or response.status_code >= 500:
                    raise FetchError(f"HTTP {response.status_code} for {url}")
                response.raise_for_status()
                return JSONFetchResult(
                    data=response.json(),
                    status_code=response.status_code,
                    url=str(response.url),
                )
            except (
                ValueError,
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
                FetchError,
            ) as exc:
                last_error = exc
                if _non_retryable_http_status(exc):
                    break
                if attempt >= retry_count:
                    break
                await self._backoff(attempt)

        raise FetchError(f"Failed to fetch {url}: {last_error}") from last_error

    async def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        retries: int | None = None,
    ) -> JSONFetchResult:
        return await self._request_json("GET", url, headers=headers, retries=retries)

    async def post_json(
        self,
        url: str,
        *,
        json: Any | None = None,
        headers: Mapping[str, str] | None = None,
        retries: int | None = None,
    ) -> JSONFetchResult:
        return await self._request_json("POST", url, headers=headers, json=json, retries=retries)

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json: Any | None = None,
        retries: int | None = None,
    ) -> JSONFetchResult:
        retry_count = self.retries if retries is None else max(0, retries)
        last_error: Exception | None = None

        for attempt in range(retry_count + 1):
            await self.rate_limiter.wait()
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=dict(headers or {}),
                    json=json,
                )
                if response.status_code == 429 or response.status_code >= 500:
                    raise FetchError(f"HTTP {response.status_code} for {url}")
                response.raise_for_status()
                return JSONFetchResult(
                    data=response.json(),
                    status_code=response.status_code,
                    url=str(response.url),
                )
            except (
                ValueError,
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
                FetchError,
            ) as exc:
                last_error = exc
                if _non_retryable_http_status(exc):
                    break
                if attempt >= retry_count:
                    break
                await self._backoff(attempt)

        raise FetchError(f"Failed to fetch {url}: {last_error}") from last_error


def _non_retryable_http_status(exc: Exception) -> bool:
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    status_code = exc.response.status_code
    return status_code != 429 and status_code < 500
