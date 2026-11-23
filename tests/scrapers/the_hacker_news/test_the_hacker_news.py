import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import FetchError, FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.mongo import build_mongo_document
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers import get_provider, provider_keys
from vuln_scraper.scrapers.the_hacker_news.config import LIST_URL
from vuln_scraper.scrapers.the_hacker_news.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.the_hacker_news.parsers.list import parse_rss_list
from vuln_scraper.scrapers.the_hacker_news.provider import TheHackerNewsProvider
from vuln_scraper.source_catalog import configured_source_keys
from vuln_scraper.sync_state import SyncContext


FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 23, 14, tzinfo=UTC)
FIRST_URL = "https://thehackernews.com/2026/11/new-parser-research.html"
SECOND_URL = "https://thehackernews.com/2026/11/security-research-without-cves.html"


def test_provider_is_discovered_and_enabled_by_all(tmp_path):
    config = tmp_path / "scrapers.toml"
    config.write_text('[scrapers.catch_up]\nproviders = ["all"]\n')
    provider = get_provider("the_hacker_news")
    assert isinstance(provider, TheHackerNewsProvider)
    assert "the_hacker_news" in provider_keys()
    assert "the_hacker_news" in configured_source_keys(config)
    assert provider.catch_up_full_feed
    assert not provider.stop_on_first_known
    assert provider.list_url(1) == provider.list_url(2) == LIST_URL
    assert provider.detail_url("THN-2026-11-new-parser-research") == FIRST_URL
    with pytest.raises(ValueError):
        provider.detail_url("THN-../../other-host")


def test_feed_uses_stable_permalink_ids_and_source_dates():
    xml = (FIXTURES / "list.xml").read_text()
    page = parse_rss_list(xml, page=1)
    first = page.entries[0]
    assert page.total_records == 2
    assert page.total_pages == 1
    assert first.key == "the_hacker_news:2026-11-new-parser-research"
    assert first.embedded_detail["article_url"] == FIRST_URL
    assert first.embedded_detail["published_at"] == "2026-11-23T13:22:20+00:00"
    assert first.embedded_detail["cve_ids"] == ["CVE-2026-12345"]
    assert first.embedded_detail["categories"] == ["Security", "Research"]
    changed = xml.replace("New parser research", "Revised title").replace("utm_source=rss", "utm_source=other")
    assert parse_rss_list(changed, page=1).entries[0].key == first.key


def test_feedburner_original_links_deduplication_and_untrusted_hosts():
    xml = (FIXTURES / "list.xml").read_text()
    xml = xml.replace(f"{FIRST_URL}?utm_source=rss</link>",
                      f"https://feedproxy.google.com/example</link><feedburner:origLink>{FIRST_URL}</feedburner:origLink>")
    root = ElementTree.fromstring(xml)
    channel = root.find("channel")
    channel.append(ElementTree.fromstring(ElementTree.tostring(channel.find("item"))))
    assert len(parse_rss_list(ElementTree.tostring(root), page=1).entries) == 2
    hostile = xml.replace("thehackernews.com", "thehackernews.com.evil.example")
    with pytest.raises(ValueError, match="no valid articles"):
        parse_rss_list(hostile, page=1)


@pytest.mark.parametrize("xml", ["<rss>", "<html>Denied</html>", "<rss/>",
                                     "<rss><channel><item><title>Bad item</title></item></channel></rss>"])
def test_malformed_feeds_are_failures(xml):
    with pytest.raises(ValueError, match="The Hacker News"):
        parse_rss_list(xml, page=1)


def test_empty_feed_and_more_than_fifty_articles():
    assert parse_rss_list("<rss><channel/></rss>", page=1).exhausted
    items = "".join(f"<item><title>Story {i}</title><link>https://thehackernews.com/2026/11/story-{i}.html</link></item>"
                    for i in range(60))
    assert len(parse_rss_list(f"<rss><channel>{items}</channel></rss>", page=1).entries) == 60


def test_full_article_extraction_and_shared_mongo_schema():
    provider = TheHackerNewsProvider()
    entry = provider.parse_list((FIXTURES / "list.xml").read_text(), page=1).entries[0]
    detail = provider.finalize_detail(provider.parse_detail((FIXTURES / "detail.html").read_text()).to_dict(),
                                      entry=entry, detail_url=FIRST_URL)
    assert "complete second paragraph" in detail["content"]
    assert "First finding\nSecond finding" in detail["content"]
    assert "must not be included" not in detail["content"]
    assert detail["author"] == "Example Researcher"
    assert detail["published_at"] == "2026-11-23T13:22:00+00:00"
    assert detail["updated_at"] == "2026-11-23T13:22:20+00:00"
    assert detail["categories"] == ["Application Security", "Security", "Research"]
    assert "https://example.org/research" in detail["reference_links"]
    assert "https://example.org/image.jpg" not in detail["reference_links"]
    document = build_mongo_document(entry.to_record(detail, detail_url=FIRST_URL), {"scraped_at": NOW.isoformat()})
    validate_v2_document(document, "news")
    assert document["_id"] == entry.key
    assert document["source"]["provider"] == "the_hacker_news"
    assert document["published_at"] == datetime(2026, 11, 23, 13, 22, tzinfo=UTC)
    assert document["cve_ids"] == ["CVE-2026-12345", "CVE-2026-54321"]
    assert "severity" not in document
    assert "_list_summary" not in document["details"]


@pytest.mark.parametrize("html", ["<html><h1>Access denied</h1></html>",
                                      '<h1 class="story-title">Story</h1><div class="articlebody"></div>'])
def test_missing_full_article_is_not_a_successful_detail(html):
    with pytest.raises(ValueError, match="The Hacker News detail page"):
        parse_detail_page(html)


class FakeClient:
    def __init__(self):
        self.feed = (FIXTURES / "list.xml").read_text()
        self.detail = (FIXTURES / "detail.html").read_text()
        self.fail_details = False
        self.old_updated_today = False
        self.urls = []

    async def get_html(self, url):
        self.urls.append(url)
        if url == LIST_URL:
            return FetchResult(html=self.feed, status_code=200, url=url)
        assert url in {FIRST_URL, SECOND_URL}
        if self.fail_details:
            raise FetchError("HTTP 503", status_code=503)
        html = self.detail
        if url == SECOND_URL:
            html = html.replace("new-parser-research", "security-research-without-cves")
            html = html.replace("New parser research", "Security research without CVEs")
            html = html.replace("2026-11-23", "2026-11-10")
            html = html.replace("CVE-2026-12345", "research").replace("CVE-2026-54321", "research")
            if self.old_updated_today:
                html = html.replace('dateModified" content="2026-11-10', 'dateModified" content="2026-11-23')
        return FetchResult(html=html, status_code=200, url=url)


def run_sync(tmp_path, collection, client, *, limit=10, hour=0):
    settings = ScraperSettings(data_dir=tmp_path, mongo_enabled=True, mongo_config_file=None,
                               mongo_collection="news", mongo_conflict="overwrite", scrapers_config_file=None,
                               request_delay=0, retries=0, concurrency=1, limit=limit)
    runner = ScraperRunner(settings, provider=TheHackerNewsProvider(),
                           mongo_client_factory=fake_mongo_factory(collection),
                           sync_context=SyncContext(until=NOW + timedelta(minutes=hour), max_pages=10, batch_size=2))
    return asyncio.run(runner._run_with_client(client))


def test_catch_up_excludes_old_articles_and_is_idempotent(tmp_path):
    collection, client = FakeMongoCollection(), FakeClient()
    first = run_sync(tmp_path, collection, client)
    assert first["mongo_sync"]["inserted"] == 1
    assert first["sync"]["outside_window"] == 1
    assert first["sync"]["incremental_status"] == "up_to_date"
    second = run_sync(tmp_path, collection, client, hour=1)
    assert second["mongo_sync"]["inserted"] == second["mongo_sync"]["overwritten"] == 0
    assert second["mongo_sync"]["unchanged"] == 1
    client.detail = client.detail.replace("complete second paragraph", "revised full paragraph")
    revised = run_sync(tmp_path, collection, client, hour=2)
    assert revised["mongo_sync"]["overwritten"] == 1


def test_old_article_with_current_revision_and_without_cves_is_valid(tmp_path):
    collection, client = FakeMongoCollection(), FakeClient()
    client.old_updated_today = True
    result = run_sync(tmp_path, collection, client)
    assert result["mongo_sync"]["inserted"] == 2
    story = collection.documents["the_hacker_news:2026-11-security-research-without-cves"]
    assert not story.get("cve_ids")
    assert "severity" not in story


def test_limit_resumes_unfinished_feed(tmp_path):
    collection, client = FakeMongoCollection(), FakeClient()
    client.old_updated_today = True
    first = run_sync(tmp_path, collection, client, limit=1)
    assert first["sync"]["incremental_status"] == "partial"
    second = run_sync(tmp_path, collection, client, limit=1, hour=1)
    assert second["sync"]["incremental_status"] == "up_to_date"
    assert len(collection.documents) == 2


def test_failed_detail_keeps_full_record_and_recovers(tmp_path):
    collection, client = FakeMongoCollection(), FakeClient()
    run_sync(tmp_path, collection, client)
    client.fail_details = True
    failed = run_sync(tmp_path, collection, client, hour=1)
    assert failed["sync"]["pending_retries"] >= 1
    assert all("complete second paragraph" in d["details"]["content"] for d in collection.documents.values())
    client.fail_details = False
    recovered = run_sync(tmp_path, collection, client, hour=2)
    assert recovered["sync"]["pending_retries"] == 0


def test_malformed_feed_does_not_fall_back_or_advance_sync(tmp_path):
    collection, client = FakeMongoCollection(), FakeClient()
    client.feed = "<html>Not RSS</html>"
    result = run_sync(tmp_path, collection, client)
    assert client.urls == [LIST_URL]
    assert not collection.documents
    assert result["sync"]["incremental_status"] == "error"
