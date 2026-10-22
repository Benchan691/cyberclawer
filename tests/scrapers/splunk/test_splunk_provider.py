import asyncio
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers import SplunkProvider, get_provider, provider_keys


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
    assert provider.list_url(1) == "https://advisory.splunk.com/advisories"
    assert provider.list_url(99) == "https://advisory.splunk.com/advisories"
    assert provider.detail_url("SPLUNK-SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"
    assert provider.detail_url("SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"


def test_splunk_provider_rejects_invalid_detail_id() -> None:
    with pytest.raises(ValueError):
        SplunkProvider().detail_url("SPLUNK-2026-0516")


@pytest.mark.parametrize("updated_since", [None, "2026-10-22T00:00:00+08:00"])
def test_splunk_archive_http_fetch_syncs_complete_grouped_advisory(tmp_path, updated_since) -> None:
    urls: list[str] = []
    collection = FakeMongoCollection()

    def respond(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        fixtures = {
            "https://advisory.splunk.com/advisories": "list_grouped.html",
            "https://advisory.splunk.com/advisories/SVD-2026-1010": "detail_grouped.html",
        }
        assert str(request.url) in fixtures
        return httpx.Response(
            200,
            text=(FIXTURES / fixtures[str(request.url)]).read_text(encoding="utf-8"),
            headers={"Content-Type": "text/html"},
        )

    settings = ScraperSettings(
        data_dir=tmp_path,
        limit=1,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        error_log=None,
    )

    async def run() -> dict:
        async with ScraperClient(delay=0, retries=0) as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            return await ScraperRunner(
                settings,
                provider=SplunkProvider(),
                mongo_client_factory=fake_mongo_factory(collection),
                updated_since=datetime.fromisoformat(updated_since) if updated_since else None,
            )._run_with_client(client)

    output = asyncio.run(run())

    assert urls == [
        "https://advisory.splunk.com/advisories",
        "https://advisory.splunk.com/advisories/SVD-2026-1010",
    ]
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
