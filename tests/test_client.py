import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from vuln_scraper.browser import BrowserFetchResult
from vuln_scraper.client import ScraperClient, FetchError


def test_scraper_client_builds_default_httpx_client() -> None:
    captured: dict[str, object] = {}

    class RecordingAsyncClient:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            return None

    with patch("vuln_scraper.client.httpx.AsyncClient", RecordingAsyncClient):
        client = ScraperClient(delay=0, retries=0)

    assert "proxy" not in captured
    assert "trust_env" not in captured
    assert "verify" not in captured
    assert client is not None


def test_get_json_does_not_retry_non_retryable_4xx() -> None:
    async def run() -> int:
        fake_client = FakeHTTPClient(status_code=403)
        client = ScraperClient(delay=0, retries=3, timeout=1)
        await client._client.aclose()
        client._client = fake_client
        try:
            with pytest.raises(FetchError, match="403"):
                await client.get_json("https://example.test/api")
        finally:
            await client.aclose()
        return fake_client.calls

    assert asyncio.run(run()) == 1


def test_backoff_uses_configured_base_and_max() -> None:
    client = ScraperClient(
        delay=0,
        retries=0,
        backoff_base=2.0,
        backoff_max=5.0,
        backoff_jitter=0.0,
    )

    async def run() -> float:
        with patch("vuln_scraper.client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            await client._backoff(2)
            return sleep.await_args.args[0]

    assert asyncio.run(run()) == 5.0


def test_backoff_scales_with_attempt() -> None:
    client = ScraperClient(
        delay=0,
        retries=0,
        backoff_base=1.0,
        backoff_max=30.0,
        backoff_jitter=0.0,
    )

    async def run() -> float:
        with patch("vuln_scraper.client.asyncio.sleep", new_callable=AsyncMock) as sleep:
            await client._backoff(1)
            return sleep.await_args.args[0]

    assert asyncio.run(run()) == 2.0


def test_refresh_session_replaces_http_client_and_clears_cookies() -> None:
    async def run() -> tuple[str | None, bool, str | None]:
        client = ScraperClient(
            delay=0,
            retries=0,
            headers={"User-Agent": "initial-ua"},
        )
        client._client.cookies.set("session", "old", domain="example.test", path="/")
        old_client_id = id(client._client)
        await client.refresh_session({"User-Agent": "rotated-ua"})
        new_client_id = id(client._client)
        request = client._client.build_request("GET", "https://example.test/")
        await client.aclose()
        return request.headers.get("User-Agent"), old_client_id != new_client_id, request.headers.get("cookie")

    user_agent, replaced, cookie_header = asyncio.run(run())
    assert user_agent == "rotated-ua"
    assert replaced
    assert not cookie_header


def test_browser_fetch_cookies_are_reused_in_memory() -> None:
    client = ScraperClient(delay=0, retries=0)
    client.browser_fetcher = FakeBrowserFetcher(
        cookies=[
            {
                "name": "aliyungf_tc",
                "value": "token",
                "domain": "avd.aliyun.com",
                "path": "/",
                "secure": True,
            }
        ]
    )

    async def run() -> str:
        try:
            await client._get_with_browser("https://avd.aliyun.com/high-risk/list?page=1")
            request = client._client.build_request("GET", "https://avd.aliyun.com/high-risk/list?page=1")
            return request.headers.get("cookie", "")
        finally:
            await client.aclose()

    assert asyncio.run(run()) == "aliyungf_tc=token"


class FakeHTTPClient:
    def __init__(self, *, status_code: int) -> None:
        self.status_code = status_code
        self.calls = 0

    async def request(self, method: str, url: str, *, headers=None, json=None):
        self.calls += 1
        return httpx.Response(
            self.status_code,
            request=httpx.Request(method, url),
            json={"error": "forbidden"},
        )

    async def aclose(self) -> None:
        return None


class FakeBrowserFetcher:
    def __init__(self, *, cookies) -> None:
        self.cookies = cookies

    async def fetch(self, url: str) -> BrowserFetchResult:
        return BrowserFetchResult(
            html="<html><table><tr><td>ok</td></tr></table></html>",
            url=url,
            status_code=200,
            cookies=self.cookies,
        )
