import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.catch_up import providers_for_catch_up
from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers import GovCERTProvider, get_provider, provider_keys
from vuln_scraper.source_catalog import configured_source_keys
from vuln_scraper.sync_state import SyncContext


FIXTURES = Path(__file__).parent / "fixtures"


def test_govcert_provider_urls_and_registry() -> None:
    provider = GovCERTProvider()

    assert "govcert" in provider_keys()
    assert get_provider("govcert").key == "govcert"
    assert provider.source_url == "https://www.govcert.gov.hk/en/alerts.php"
    assert provider.list_url(1) == "https://www.govcert.gov.hk/en/rss_security_alerts.xml"
    assert provider.list_url(2) == "https://www.govcert.gov.hk/en/rss_security_alerts.xml"
    assert provider.detail_url("GOVCERT-1894") == "https://www.govcert.gov.hk/en/alerts_detail.php?id=1894"
    assert provider.default_mongo_collection == "govcert"
    assert provider.stop_on_first_known


@pytest.mark.parametrize("identity", ["", "GOVCERT-abc", "GOVCERT-1/2", "GOVCERT--1"])
def test_govcert_rejects_invalid_detail_ids(identity: str) -> None:
    with pytest.raises(ValueError, match="invalid GovCERT alert identifier"):
        GovCERTProvider().detail_url(identity)


def test_govcert_is_enabled_for_catch_up_and_source_catalog() -> None:
    config = Path(__file__).resolve().parents[3] / "scrapers.toml"

    providers = providers_for_catch_up(ScraperSettings(scrapers_config_file=config))

    assert "govcert" in [provider.key for provider in providers]
    assert "govcert" in configured_source_keys(config)


@pytest.mark.parametrize("xml", [
    "<rss>",
    "<html><body>Temporarily unavailable</body></html>",
    "<rss><channel><item><title>Other site</title><link>https://example.test/</link></item></channel></rss>",
])
def test_govcert_reports_invalid_rss_as_a_list_failure(xml: str) -> None:
    with pytest.raises(FetchError, match="Invalid GovCERT security alerts feed"):
        GovCERTProvider().parse_list(xml, page=1)


def test_govcert_rss_syncs_full_alerts_and_detail_only_revisions(tmp_path) -> None:
    urls: list[str] = []
    collection = FakeMongoCollection()
    now = datetime(2026, 6, 1, 4, tzinfo=UTC)
    revised = False

    def respond(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        assert request.url.host == "www.govcert.gov.hk"
        if request.url.path == "/en/rss_security_alerts.xml":
            assert not request.url.query
            return httpx.Response(200, text=(FIXTURES / "list.xml").read_text(encoding="utf-8"),
                                  headers={"Content-Type": "application/xml"})
        assert request.url.path == "/en/alerts_detail.php"
        code = request.url.params["id"]
        name = {"1894": "detail_high_threat.html", "1893": "detail_multi_cve.html"}[code]
        detail = (FIXTURES / name).read_text(encoding="utf-8")
        if revised and code == "1893":
            detail = detail.replace(
                '<p class="text-content">Published on: 29 May 2026</p>',
                '<p class="text-content">Published on: 29 May 2026</p>'
                '<p class="text-content">Last update on: 02 June 2026</p>',
            )
        return httpx.Response(200, text=detail, headers={"Content-Type": "text/html"})

    settings = ScraperSettings(
        data_dir=tmp_path, limit=2, mongo_enabled=True, mongo_collection="news",
        mongo_config_file=None, scrapers_config_file=None, mongo_conflict="overwrite",
        request_delay=0, retries=0, concurrency=1, error_log=None,
    )

    async def run(at: datetime, days: int) -> dict:
        async with ScraperClient(delay=0, retries=0) as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            runner = ScraperRunner(
                settings, provider=GovCERTProvider(),
                mongo_client_factory=fake_mongo_factory(collection),
                sync_context=SyncContext(until=at, overlap_days=days),
            )
            assert runner.settings.mongo_collection == "news"
            return await runner._run_with_client(client)

    output = asyncio.run(run(now, days=4))

    expected_urls = [
        "https://www.govcert.gov.hk/en/rss_security_alerts.xml",
        "https://www.govcert.gov.hk/en/alerts_detail.php?id=1894",
        "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893",
    ]
    assert urls == expected_urls
    assert output["failed"] == []
    assert output["mongo_sync"]["errors"] == []
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"govcert:1894", "govcert:1893"}
    for document in collection.documents.values():
        validate_v2_document(document, "news")
        assert document["source"]["provider"] == "govcert"
        assert document["severity"] == {"1894": "Critical", "1893": "Medium"}[document["code"]]
        assert "severity" not in document["details"]
        assert "Recommendation:" in document["details"]["content"]
    assert collection.documents["govcert:1893"]["cve_ids"] == ["CVE-2026-9872", "CVE-2026-10022"]
    published_at = collection.documents["govcert:1893"]["published_at"]

    urls.clear()
    revised = True
    output = asyncio.run(run(now + timedelta(days=1), days=1))

    assert urls == expected_urls
    assert output["failed"] == []
    assert output["mongo_sync"]["overwritten"] == 1
    assert output["sync"]["outside_window"] == 1
    updated = collection.documents["govcert:1893"]
    assert updated["published_at"] == published_at
    assert updated["updated_at"] == datetime(2026, 6, 1, 16, tzinfo=UTC)
    assert "Recommendation:" in updated["details"]["content"]
