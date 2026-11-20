import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers import SplunkProvider, get_provider, provider_keys
from vuln_scraper.sync_state import SyncContext


FIXTURES = Path(__file__).parent / "fixtures"


def test_splunk_provider_registry_and_defaults() -> None:
    provider = get_provider("splunk")

    assert isinstance(provider, SplunkProvider)
    assert "splunk" in provider_keys()
    assert provider.content_type == "html"
    assert provider.default_request_delay == 1.0
    assert provider.stop_on_first_known
    assert provider.default_mongo_collection == "splunk"


def test_splunk_provider_urls() -> None:
    provider = SplunkProvider()

    assert provider.source_url == "https://advisory.splunk.com/advisories"
    assert provider.list_url(1) == "https://advisory.splunk.com/feed.xml"
    assert provider.list_url(99) == "https://advisory.splunk.com/feed.xml"
    assert provider.detail_url("SPLUNK-SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"
    assert provider.detail_url("SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"


def test_splunk_provider_rejects_invalid_detail_id() -> None:
    with pytest.raises(ValueError):
        SplunkProvider().detail_url("SPLUNK-2026-0516")


@pytest.mark.parametrize("malformed", [
    "<rss>",
    "<html><body>Temporarily unavailable</body></html>",
    "<rss><channel><item><link>https://example.test/SVD-2026-1010</link></item></channel></rss>",
])
def test_splunk_reports_an_invalid_feed_as_a_list_failure(malformed) -> None:
    with pytest.raises(FetchError, match="Invalid Splunk advisory feed"):
        SplunkProvider().parse_list(malformed, page=1)


def test_splunk_rss_syncs_full_advisory_and_later_edits_with_unchanged_feed(tmp_path) -> None:
    urls: list[str] = []
    collection = FakeMongoCollection()
    feed_url = "https://advisory.splunk.com/feed.xml"
    detail_url = "https://advisory.splunk.com/advisories/SVD-2026-1010"
    rss = (FIXTURES / "list_grouped.xml").read_text(encoding="utf-8")
    detail = (FIXTURES / "detail_grouped.html").read_text(encoding="utf-8")
    now = datetime(2026, 10, 22, 3, tzinfo=UTC)

    def respond(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        urls.append(url)
        if url == feed_url:
            return httpx.Response(200, text=rss, headers={"Content-Type": "application/xml"})
        assert url == detail_url
        return httpx.Response(200, text=detail, headers={"Content-Type": "text/html"})

    settings = ScraperSettings(
        data_dir=tmp_path,
        limit=1,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        error_log=None,
    )

    async def run(until: datetime) -> dict:
        async with ScraperClient(delay=0, retries=0) as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            return await ScraperRunner(
                settings,
                provider=SplunkProvider(),
                mongo_client_factory=fake_mongo_factory(collection),
                sync_context=SyncContext(until=until),
            )._run_with_client(client)

    output = asyncio.run(run(now))

    assert urls == [feed_url, detail_url]
    assert output["failed"] == []
    assert output["mongo_sync"]["errors"] == []
    assert output["mongo_sync"]["inserted"] == 1
    document = collection.documents["splunk:SVD-2026-1010"]
    validate_v2_document(document, "news")
    assert document["cve_ids"] == ["CVE-2026-76303", "CVE-2026-76406"]
    assert document["severity"] == "High"
    assert document["details"]["description"] == "Multiple security vulnerabilities were fixed in Splunk SOAR."
    assert "The second vulnerability" in document["details"]["cve_details"]
    assert "The first vulnerability" in document["details"]["content"]
    assert "The second vulnerability" in document["details"]["content"]
    assert "obtain the maintenance package from your support contact" in document["details"]["content"]
    assert document["updated_at"] > document["published_at"]

    urls.clear()
    detail = detail.replace("Clarified mitigations.", "Revised package guidance.")
    revised = asyncio.run(run(now + timedelta(hours=1)))

    assert urls == [feed_url, detail_url]
    assert revised["mongo_sync"]["overwritten"] == 1
    assert collection.documents["splunk:SVD-2026-1010"]["details"]["changelog"] == (
        "2026-10-22: Revised package guidance."
    )
