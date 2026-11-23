import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers import get_provider
from vuln_scraper.sync_state import SyncContext, SyncStateStore


FEED = Path(__file__).parent / "fixtures" / "feed.xml"
FEED_URL = "https://www.bleepingcomputer.com/feed/"
ARTICLE_URL = "https://www.bleepingcomputer.com/news/security/example-vendor-patches/"
ARTICLE_ID = "bleepingcomputer:security/example-vendor-patches"
NOW = datetime(2026, 11, 13, 9, 30, tzinfo=UTC)


def test_provider_urls_and_defaults():
    provider = get_provider("bleepingcomputer")
    assert provider.list_url(1) == FEED_URL
    assert provider.detail_url("BLEEPINGCOMPUTER-security/example-vendor-patches") == ARTICLE_URL
    assert provider.content_type == "html"
    assert provider.stop_on_first_known is False
    with pytest.raises(ValueError, match="article identifier"):
        provider.detail_url("../../example")


def _run(tmp_path, monkeypatch, news, *, feed, now=NOW, days=1):
    requests = []

    def respond(request):
        requests.append(str(request.url))
        assert str(request.url) == FEED_URL
        assert "application/rss+xml" in request.headers["Accept"]
        return httpx.Response(200, content=feed, headers={"Content-Type": "text/xml"})

    def make_http_client(client):
        return httpx.AsyncClient(headers=client._default_headers, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(ScraperClient, "_build_http_client", make_http_client)
    settings = ScraperSettings(
        data_dir=tmp_path, retries=0, request_delay=0, scrapers_config_file=None,
        mongo_config_file=None, mongo_enabled=True, mongo_collection="news",
        mongo_conflict="overwrite",
    )
    runner = ScraperRunner(
        settings, provider=get_provider("bleepingcomputer"),
        mongo_client_factory=fake_mongo_factory(news),
        sync_context=SyncContext(until=now, overlap_days=days),
    )
    output = asyncio.run(runner.run())
    assert requests == [FEED_URL]
    return output


def test_run_filters_by_hong_kong_date_and_saves_feed_metadata(tmp_path, monkeypatch):
    news = FakeMongoCollection()
    feed = FEED.read_bytes()
    output = _run(tmp_path, monkeypatch, news, feed=feed)
    assert output["mongo_sync"]["errors"] == []
    assert output["mongo_sync"]["inserted"] == 2
    assert output["sync"]["outside_window"] == 1
    assert set(news.documents) == {ARTICLE_ID, "bleepingcomputer:microsoft/example-release"}
    article = news.documents[ARTICLE_ID]
    assert article["source"]["provider"] == "bleepingcomputer"
    assert article["source"]["detail_url"] == ARTICLE_URL
    assert article["published_at"] == datetime(2026, 11, 13, 1, 15, tzinfo=UTC)
    assert article["cve_ids"] == ["CVE-2026-12345", "CVE-2026-23456"]
    assert article["details"]["author"] == "Test Reporter"
    assert article["details"]["categories"] == ["Security", "Software"]

    wider = _run(tmp_path, monkeypatch, news, feed=feed, now=NOW + timedelta(hours=1), days=2)
    assert wider["mongo_sync"]["inserted"] == 1
    assert wider["mongo_sync"]["unchanged"] == 2
    assert "bleepingcomputer:hardware/example-older-post" in news.documents


def test_retry_uses_saved_excerpt_after_feed_and_local_cache_change(tmp_path, monkeypatch):
    news = FakeMongoCollection(fail_insert_once_for=ARTICLE_ID)
    first = _run(tmp_path, monkeypatch, news, feed=FEED.read_bytes())
    assert first["sync"]["pending_retries"] == 1
    store = SyncStateStore(news.sync_collections["news_sync_state"], "bleepingcomputer")
    original_observation = datetime.fromisoformat(store.failures()[0]["observed_at"])
    for path in (tmp_path / "sync-cache" / "bleepingcomputer").glob("*.json"):
        path.unlink()

    empty_feed = b"<rss><channel/></rss>"
    news.fail_insert_once_for = ARTICLE_ID
    second = _run(tmp_path, monkeypatch, news, feed=empty_feed, now=NOW + timedelta(minutes=15))
    assert second["sync"]["pending_retries"] == 1

    third = _run(tmp_path, monkeypatch, news, feed=empty_feed, now=NOW + timedelta(minutes=30))
    assert third["sync"]["pending_retries"] == 0
    assert third["mongo_sync"]["inserted"] == 1
    assert news.documents[ARTICLE_ID]["details"]["author"] == "Test Reporter"
    assert news.documents[ARTICLE_ID]["observed_at"] == original_observation
