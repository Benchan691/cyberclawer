import asyncio
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import Checkpoint, ScraperRunner
from vuln_scraper.scrapers.fortiguard.config import RSS_URL
from vuln_scraper.scrapers.fortiguard.parsers.rss import parse_rss_list
from vuln_scraper.scrapers.fortiguard.provider import FortiguardProvider


FIXTURES = Path(__file__).parent / "fixtures"


def test_rss_preserves_ids_dates_and_namespaced_links_and_orders_revisions():
    page = parse_rss_list((FIXTURES / "list.xml").read_text(), page=1)

    assert [entry.key for entry in page.entries] == [
        "fortiguard:FG-IR-26-160", "fortiguard:FG-IR-26-158",
    ]
    assert page.total_pages == 1
    assert page.total_records == 2
    detail = page.entries[0].embedded_detail
    assert detail["_list_summary"] is True
    assert detail["published_date"] == "2026-08-12"
    assert detail["updated_date"] == "2026-11-08"
    assert detail["cve_ids"] == ["CVE-2026-70468"]
    assert detail["csaf_url"].endswith("_fg-ir-26-160.json")
    assert detail["cvrf_url"].endswith("/cvrf/FG-IR-26-160")


def test_runner_fetches_rss_first_and_full_advisory(tmp_path):
    provider = FortiguardProvider()
    requests = []

    def respond(request):
        requests.append(str(request.url))
        if str(request.url) == RSS_URL:
            return httpx.Response(200, text=(FIXTURES / "list.xml").read_text())
        if request.url.path == "/psirt/FG-IR-26-160":
            return httpx.Response(200, text=(FIXTURES / "detail.html").read_text())
        if request.url.path.endswith("_fg-ir-26-160.json"):
            return httpx.Response(200, json={"document": {"tracking": {"id": "FG-IR-26-160"}}})
        raise AssertionError(f"Unexpected request: {request.url}")

    settings = ScraperSettings(
        data_dir=tmp_path, limit=1, retries=1, request_delay=0,
        backoff_base=0, backoff_jitter=0, scrapers_config_file=None,
    )
    runner = ScraperRunner(settings, provider=provider)

    async def run():
        with patch.object(ScraperClient, "_build_http_client", lambda _: httpx.AsyncClient(transport=httpx.MockTransport(respond))):
            async with ScraperClient(delay=0, retries=1, backoff_base=0, backoff_jitter=0) as client:
                return await runner._run_with_client(client)

    output = asyncio.run(run())

    assert output["result_count"] == 1
    assert output["failed"] == []
    record = output["vulnerabilities"][0]
    detail = record["details"]["fortiguard"]
    assert record["source"]["detail_url"] == provider.detail_url("FG-IR-26-160")
    assert "set fgfm-peercert-withoutsn disable" in detail["content"]
    assert detail["affected_products"][1]["solution"] == "Upgrade to 7.6.2 or above"
    assert requests == [RSS_URL, record["source"]["detail_url"], detail["csaf_url"]]
    assert detail["csaf"]["document"]["tracking"]["id"] == "FG-IR-26-160"
    assert not detail.get("_list_summary")
    assert Checkpoint.load(runner.settings.checkpoint_file).failed == {}


@pytest.mark.parametrize("status", [403, 500, 503, None])
def test_feed_failure_has_no_directory_fallback(tmp_path, status):
    provider = FortiguardProvider()
    urls = []

    def respond(request):
        urls.append(str(request.url))
        if status is None:
            raise httpx.ReadTimeout("feed timed out", request=request)
        return httpx.Response(status)

    runner = ScraperRunner(ScraperSettings(data_dir=tmp_path), provider=provider)

    async def run():
        with patch.object(ScraperClient, "_build_http_client", lambda _: httpx.AsyncClient(transport=httpx.MockTransport(respond))):
            async with ScraperClient(delay=0, retries=1, backoff_base=0, backoff_jitter=0) as client:
                with pytest.raises(FetchError) as failure:
                    await runner._fetch_list_page(client, provider.list_url(1), 1)
                assert failure.value.status_code == status

    asyncio.run(run())
    assert urls == [RSS_URL] * (1 if status == 403 else 2)


@pytest.mark.parametrize("xml", [
    "<rss>",
    "<html><body>Service unavailable</body></html>",
    '<rss><channel><item><link>https://example.test/psirt/FG-IR-26-160</link></item></channel></rss>',
])
def test_invalid_feed_remains_a_fetch_failure_without_fallback(tmp_path, xml):
    provider = FortiguardProvider()
    urls = []

    def respond(request):
        urls.append(str(request.url))
        return httpx.Response(200, text=xml)

    runner = ScraperRunner(ScraperSettings(data_dir=tmp_path), provider=provider)

    async def run():
        with patch.object(ScraperClient, "_build_http_client", lambda _: httpx.AsyncClient(transport=httpx.MockTransport(respond))):
            async with ScraperClient(delay=0, retries=0) as client:
                with pytest.raises(FetchError, match=RSS_URL):
                    await runner._fetch_list_page(client, provider.list_url(1), 1)

    asyncio.run(run())
    assert urls == [RSS_URL]
