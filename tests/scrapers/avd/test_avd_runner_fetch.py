import asyncio
from pathlib import Path
from unittest.mock import patch

from vuln_scraper.config import ScraperSettings
from vuln_scraper.scrapers import get_provider
from vuln_scraper.runner import ScraperRunner

FIXTURES = Path(__file__).parent / "fixtures"


def test_fetch_avd_html_uses_sigchl_redirect(tmp_path) -> None:
    list_html = (FIXTURES / "list.html").read_text(encoding="utf-8")
    captured_urls: list[str] = []

    def fake_fetch_via_redirect(url, *, headers=None, cookies=None, proxy_url=None, timeout=30.0):
        captured_urls.append(url)
        return list_html, f"{url}&timestamp__1384=cleared", []

    settings = ScraperSettings(
        data_dir=tmp_path,
        limit=1,
        mongo_enabled=False,
        browser_fallback=False,
        request_delay=0,
        retries=0,
    ).normalized()

    runner = ScraperRunner(settings, provider=get_provider("avd"))

    async def run():
        from vuln_scraper.client import ScraperClient

        with patch(
            "vuln_scraper.scrapers.avd.h.fetch_via_redirect",
            side_effect=fake_fetch_via_redirect,
        ):
            async with ScraperClient(delay=0, retries=0) as client:
                return await runner._fetch_avd_html(
                    client,
                    "https://avd.aliyun.com/high-risk/list?page=1",
                )

    result = asyncio.run(run())

    assert captured_urls == ["https://avd.aliyun.com/high-risk/list?page=1"]
    assert "AVD-2026-10001" in result.html
