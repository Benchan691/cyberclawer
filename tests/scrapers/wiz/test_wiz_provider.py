import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import FetchError, FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers import get_provider, provider_keys
from vuln_scraper.scrapers.wiz.config import BASE_URL, LIST_URL
from vuln_scraper.scrapers.wiz.provider import WizProvider
from vuln_scraper.source_catalog import configured_source_keys
from vuln_scraper.sync_state import SyncContext


FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 18, 3, tzinfo=UTC)


def test_wiz_is_discovered_and_included_in_all_source_catalogs(tmp_path):
    provider = get_provider("wiz")
    config = tmp_path / "scrapers.toml"
    config.write_text('[scrapers.catch_up]\nproviders = ["all"]\n')

    assert isinstance(provider, WizProvider)
    assert "wiz" in provider_keys()
    assert "wiz" in configured_source_keys(config)
    assert provider.content_type == "html"
    assert provider.default_request_delay == 1.0
    assert not provider.stop_on_first_known
    assert provider.catch_up_full_feed
    assert provider.list_url(1) == LIST_URL
    assert provider.list_url(99) == LIST_URL
    assert provider.detail_url("WIZ-408d8c76-b6ae-80b2-8035-d638c24854dc") == (
        f"{BASE_URL}/408d8c76b6ae80b28035d638c24854dc"
    )
    with pytest.raises(ValueError, match="invalid Wiz incident"):
        provider.detail_url("WIZ-not-an-id")


class FakeWizClient:
    def __init__(self):
        self.urls = []
        self.feed = (FIXTURES / "list.xml").read_text()
        self.detail = (FIXTURES / "detail.html").read_text()
        self.fail_details = False

    async def get_html(self, url):
        self.urls.append(url)
        if url == LIST_URL:
            return FetchResult(html=self.feed, status_code=200, url=url)
        if url not in {f"{BASE_URL}/408d8c76b6ae80b28035d638c24854dc",
                       f"{BASE_URL}/0cd8f9b7743f43adaf3fa9c767a35f4f"}:
            raise AssertionError(f"unexpected Wiz detail URL: {url}")
        if self.fail_details:
            raise FetchError("HTTP 503", status_code=503)
        html = self.detail
        if url.endswith("0cd8f9b7743f43adaf3fa9c767a35f4f"):
            html = html.replace("example-cloud-campaign", "historical-cloud-research")
            html = html.replace("Example Cloud Campaign", "Historical Cloud Research")
            html = html.replace("October 21, 2026", "September 1, 2020")
        return FetchResult(html=html, status_code=200, url=url)


def settings(tmp_path, *, mongo_enabled=False, limit=10):
    return ScraperSettings(
        data_dir=tmp_path, mongo_enabled=mongo_enabled, mongo_config_file=None,
        mongo_collection="news", mongo_conflict="overwrite", scrapers_config_file=None,
        request_delay=0, retries=0, concurrency=1, limit=limit,
    )


def recent_articles(client):
    client.feed = client.feed.replace("Wed, 21 Oct 2026", "Wed, 18 Nov 2026")
    client.feed = client.feed.replace("Tue, 01 Sep 2020", "Wed, 18 Nov 2026")
    client.detail = client.detail.replace("October 21, 2026", "November 18, 2026")
    return client


def test_runner_uses_permanent_links_for_outdated_feed_slugs_and_respects_limit(tmp_path):
    client = FakeWizClient()
    client.feed = client.feed.replace("example-cloud-campaign", "retired-cloud-campaign-")
    output = asyncio.run(ScraperRunner(settings(tmp_path, limit=1), provider=WizProvider())._run_with_client(client))

    assert client.urls == [LIST_URL, f"{BASE_URL}/408d8c76b6ae80b28035d638c24854dc"]
    record = output["vulnerabilities"][0]
    assert record["type"] == "wiz"
    assert record["code"] == "408d8c76-b6ae-80b2-8035-d638c24854dc"
    assert "complete second paragraph" in record["details"]["wiz"]["content"]
    assert "_list_summary" not in record["details"]["wiz"]


def run_sync(tmp_path, collection, client, *, limit=10, hour=0):
    runner = ScraperRunner(
        settings(tmp_path, mongo_enabled=True, limit=limit), provider=WizProvider(),
        mongo_client_factory=fake_mongo_factory(collection),
        sync_context=SyncContext(until=NOW + timedelta(hours=hour), max_pages=10, batch_size=5),
    )
    return asyncio.run(runner._run_with_client(client))


def test_catch_up_does_not_store_backdated_articles_without_a_recent_edit(tmp_path):
    collection = FakeMongoCollection()
    client = FakeWizClient()
    first = run_sync(tmp_path, collection, client)
    assert first["mongo_sync"]["inserted"] == 0
    assert first["sync"]["outside_window"] == 2
    assert first["sync"]["incremental_status"] == "up_to_date"
    assert len(client.urls) == 3  # RSS has no edit date; confirm it from the article.


def test_old_feed_article_with_an_edit_today_is_collected(tmp_path):
    collection = FakeMongoCollection()
    client = FakeWizClient()
    client.detail = client.detail.replace("Oct 29, 2026", "Nov 18, 2026")
    first = run_sync(tmp_path, collection, client)
    assert first["mongo_sync"]["inserted"] == 2
    assert first["sync"]["outside_window"] == 0


def test_catch_up_reconciles_todays_articles_and_revisions(tmp_path):
    collection = FakeMongoCollection()
    client = recent_articles(FakeWizClient())
    first = run_sync(tmp_path, collection, client)
    assert first["mongo_sync"]["inserted"] == 2
    assert first["sync"]["outside_window"] == 0
    assert first["sync"]["incremental_status"] == "up_to_date"

    second = run_sync(tmp_path, collection, client, hour=1)
    assert second["mongo_sync"]["unchanged"] == 2
    client.detail = client.detail.replace("complete second paragraph", "revised second paragraph")
    revised = run_sync(tmp_path, collection, client, hour=2)
    assert revised["mongo_sync"]["overwritten"] == 2
    assert all("revised second paragraph" in item["details"]["content"] for item in collection.documents.values())


def test_feed_catch_up_resumes_across_limits(tmp_path):
    collection = FakeMongoCollection()
    client = recent_articles(FakeWizClient())
    first = run_sync(tmp_path, collection, client, limit=1)
    assert first["sync"]["incremental_status"] == "partial"
    second = run_sync(tmp_path, collection, client, limit=1, hour=1)
    assert second["sync"]["incremental_status"] == "up_to_date"
    assert len(collection.documents) == 2


def test_failed_detail_preserves_full_documents_and_is_retried(tmp_path):
    collection = FakeMongoCollection()
    client = recent_articles(FakeWizClient())
    run_sync(tmp_path, collection, client)
    client.fail_details = True
    failed = run_sync(tmp_path, collection, client, hour=1)
    assert failed["sync"]["pending_retries"] == 2
    assert all("complete second paragraph" in item["details"]["content"] for item in collection.documents.values())
    client.fail_details = False
    recovered = run_sync(tmp_path, collection, client, hour=2)
    assert recovered["sync"]["pending_retries"] == 0
    assert recovered["sync"]["incremental_status"] == "up_to_date"
