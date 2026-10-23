import asyncio
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.catch_up import providers_for_catch_up
from vuln_scraper.client import ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers import GovCERTProvider, get_provider, provider_keys
from vuln_scraper.source_catalog import configured_source_keys


FIXTURES = Path(__file__).parent / "fixtures"


def test_govcert_provider_urls_and_registry() -> None:
    provider = GovCERTProvider()

    assert "govcert" in provider_keys()
    assert get_provider("govcert").key == "govcert"
    assert provider.list_url(1) == "https://www.govcert.gov.hk/en/alerts.php?page=1"
    assert provider.list_url(2) == "https://www.govcert.gov.hk/en/alerts.php?page=2"
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


@pytest.mark.parametrize("updated_since, expected_ids", [
    (None, ["1894", "1893"]),
    ("2026-06-01T00:00:00+08:00", ["1894"]),
])
def test_govcert_fetches_full_alerts_and_syncs_to_shared_mongo(tmp_path, updated_since, expected_ids) -> None:
    urls: list[str] = []
    collection = FakeMongoCollection()

    def respond(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        assert request.url.host == "www.govcert.gov.hk"
        if request.url.path == "/en/alerts.php":
            assert request.url.params.get("page") == "1"
            name = "list.html"
        else:
            assert request.url.path == "/en/alerts_detail.php"
            name = {"1894": "detail_high_threat.html", "1893": "detail_multi_cve.html"}[
                request.url.params["id"]
            ]
        return httpx.Response(200, text=(FIXTURES / name).read_text(encoding="utf-8"))

    settings = ScraperSettings(
        data_dir=tmp_path, limit=2, mongo_enabled=True, mongo_collection="news",
        mongo_config_file=None, scrapers_config_file=None, mongo_conflict="overwrite",
        request_delay=0, retries=0, concurrency=1, error_log=None,
    )

    async def run() -> dict:
        async with ScraperClient(delay=0, retries=0) as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            runner = ScraperRunner(
                settings, provider=GovCERTProvider(),
                mongo_client_factory=fake_mongo_factory(collection),
                updated_since=datetime.fromisoformat(updated_since) if updated_since else None,
            )
            assert runner.settings.mongo_collection == "news"
            return await runner._run_with_client(client)

    output = asyncio.run(run())

    assert urls == [
        "https://www.govcert.gov.hk/en/alerts.php?page=1",
        "https://www.govcert.gov.hk/en/alerts_detail.php?id=1894",
        "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893",
    ]
    assert output["failed"] == []
    assert output["mongo_sync"]["errors"] == []
    assert output["mongo_sync"]["inserted"] == len(expected_ids)
    assert set(collection.documents) == {f"govcert:{code}" for code in expected_ids}
    for document in collection.documents.values():
        validate_v2_document(document, "news")
        assert document["source"]["provider"] == "govcert"
        assert document["severity"] == {"1894": "Critical", "1893": "Medium"}[document["code"]]
        assert "severity" not in document["details"]
        assert "Recommendation:" in document["details"]["content"]
    if "1893" in expected_ids:
        assert collection.documents["govcert:1893"]["cve_ids"] == ["CVE-2026-9872", "CVE-2026-10022"]
    if updated_since:
        assert output["stop_reason"] == "timestamp_boundary"
