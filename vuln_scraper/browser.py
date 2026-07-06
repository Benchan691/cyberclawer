from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DEFAULT_USER_AGENT


@dataclass(slots=True)
class BrowserFetchResult:
    html: str
    url: str
    status_code: int | None
    cookies: list[dict[str, Any]]


class BrowserVerificationTimeout(RuntimeError):
    """Raised when a manual verification page never reaches scraper content."""


class BrowserHTMLFetcher:
    def __init__(
        self,
        *,
        headless: bool = True,
        timeout_ms: int = 30_000,
        chrome_executable: str | None = None,
        user_data_dir: str | Path | None = None,
        manual_verification: bool = False,
        proxy_url: str | None = None,
    ) -> None:
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.chrome_executable = chrome_executable
        self.proxy_url = proxy_url.strip() if proxy_url and proxy_url.strip() else None
        self.user_data_dir = Path(user_data_dir) if user_data_dir is not None else None
        self.manual_verification = manual_verification
        self._playwright = None
        self._browser = None
        self._context = None
        self._persistent_context = False
        self._manual_page = None

    async def __aenter__(self) -> "BrowserHTMLFetcher":
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed. Install with `pip install -e .[browser]` "
                "or run without --browser-fallback."
            ) from exc

        self._playwright = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        if self.chrome_executable:
            launch_kwargs["executable_path"] = self.chrome_executable

        context_kwargs: dict[str, Any] = {
            "user_agent": DEFAULT_USER_AGENT,
            "locale": "zh-CN",
            "viewport": {"width": 1440, "height": 1100},
            "extra_http_headers": {"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
        }
        if self.proxy_url:
            context_kwargs["proxy"] = {"server": self.proxy_url}
            context_kwargs["ignore_https_errors"] = True
        if self.user_data_dir is not None:
            self.user_data_dir.mkdir(parents=True, exist_ok=True)
            self._context = await self._playwright.chromium.launch_persistent_context(
                str(self.user_data_dir),
                **launch_kwargs,
                **context_kwargs,
            )
            self._browser = self._context.browser
            self._persistent_context = True
        else:
            self._browser = await self._playwright.chromium.launch(**launch_kwargs)
            self._context = await self._browser.new_context(**context_kwargs)

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._manual_page is not None and not self._manual_page.is_closed():
            await self._manual_page.close()
        if self._context is not None:
            await self._context.close()
        if self._browser is not None and not self._persistent_context:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def fetch(self, url: str) -> BrowserFetchResult:
        if self._context is None:
            raise RuntimeError("BrowserHTMLFetcher must be used as an async context manager.")

        page = await self._context.new_page()
        response = None
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            ready = await self._wait_for_real_content(page)
            if not ready and self.manual_verification:
                timeout_seconds = max(1, self.timeout_ms // 1000)
                raise BrowserVerificationTimeout(
                    "verification was not completed before "
                    f"the {timeout_seconds}s browser timeout"
                )
            html = await page.content()
            cookies = await self._context.cookies(url)
            return BrowserFetchResult(
                html=html,
                url=page.url,
                status_code=response.status if response else None,
                cookies=cookies,
            )
        finally:
            await page.close()

    async def verify(self, url: str) -> BrowserFetchResult:
        if self._context is None:
            raise RuntimeError("BrowserHTMLFetcher must be used as an async context manager.")

        if self._manual_page is None or self._manual_page.is_closed():
            self._manual_page = await self._context.new_page()
        page = self._manual_page
        response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        try:
            await page.bring_to_front()
        except Exception:
            pass
        return BrowserFetchResult(
            html=await page.content(),
            url=page.url,
            status_code=response.status if response else None,
            cookies=await self._context.cookies(url),
        )

    async def cookies(self, url: str) -> list[dict[str, Any]]:
        if self._context is None:
            raise RuntimeError("BrowserHTMLFetcher must be used as an async context manager.")
        return await self._context.cookies(url)

    async def _content_ready(self, page) -> bool:
        try:
            return await page.evaluate(
                """() => {
                    const body = document.body ? document.body.innerText : "";
                    return Boolean(
                        document.querySelector("table") ||
                        document.querySelector("span.header__title__text") ||
                        document.querySelector(".CoveoResult") ||
                        document.querySelector("c-quantic-result") ||
                        document.querySelector(".quantic-result") ||
                        document.querySelector(".security-advisory") ||
                        document.querySelector(".news-list") ||
                        document.querySelector(".article-list") ||
                        document.querySelector(".blkContainerSblk") ||
                        document.querySelector(".gg_detail") ||
                        body.includes("AVD-") ||
                        body.includes("CNVD-") ||
                        body.includes("JSA") ||
                        body.includes("Security Advisories") ||
                        body.includes("Security Advisory") ||
                        body.includes("Hikvision") ||
                        body.includes("漏洞标题") ||
                        body.includes("危害级别") ||
                        body.includes("漏洞名称")
                    );
                }"""
            )
        except Exception:
            return False

    async def _wait_for_real_content(self, page) -> bool:
        deadline = asyncio.get_running_loop().time() + (self.timeout_ms / 1000)
        last_html = ""

        while asyncio.get_running_loop().time() < deadline:
            if await self._content_ready(page):
                try:
                    await page.wait_for_load_state("networkidle", timeout=5_000)
                except Exception:
                    pass
                return True

            current_html = await page.content()
            if current_html != last_html:
                last_html = current_html
            await asyncio.sleep(0.5)

        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
        return False
