import asyncio
import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

from tests.test_runner import (
    FakeMongoCollection, FakeMSRCClient, fake_mongo_factory, paloalto_detail_html,
)
from tests.scrapers.zimbra.test_zimbra_parsers import DETAIL_HTML as ZIMBRA_DETAIL
from vuln_scraper.client import FetchError, FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.mongo import build_mongo_document
from vuln_scraper.scrapers import get_provider
from vuln_scraper.sync_state import SyncContext, retry_entry_data, restore_entry


NOW = datetime(2026, 11, 24, 9, tzinfo=UTC)
HUAWEI = Path(__file__).parent / "scrapers/huawei_sa/fixtures"


def rss(items):
    return '<rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>' + "".join(items) + '</channel></rss>'


def item(title, url, *, date="Tue, 24 Nov 2026 01:00:00 GMT", body="", guid="", revision="1.0"):
    return (f'<item Revision="{revision}"><title>{escape(title)}</title><link>{escape(url)}</link>'
            f'<guid>{escape(guid)}</guid><pubDate>{date}</pubDate><content:encoded><![CDATA[{body}]]>'
            '</content:encoded></item>')


def msrc_feed(*cves):
    return rss([item(cve + ' Complete advisory', f'https://msrc.microsoft.com/update-guide/vulnerability/{cve}', guid=cve)
                for cve in cves])


@pytest.mark.parametrize("key", ["paloalto", "msrc", "huawei_sa", "zimbra"])
def test_four_providers_use_one_rss_page_and_reject_malformed_lists(key):
    provider = get_provider(key)
    assert provider.list_url(1) == provider.list_url(99)
    assert provider.catch_up_full_feed
    assert not provider.stop_on_first_known
    assert provider.parse_list('<rss><channel/></rss>', page=1).entries == []
    for bad in ('<html>Blocked</html>', '<rss>', '<rss><channel><item/></channel></rss>'):
        with pytest.raises(ValueError):
            provider.parse_list(bad, page=1)


def test_msrc_deduplicates_cves_using_latest_revision_and_retains_stable_ids():
    cve = "CVE-2026-41108"
    url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
    provider = get_provider("msrc")
    xml = rss([item(cve, url, guid=cve, revision="1.1"), item(cve, url, guid=cve, revision="2.0")])
    entries = provider.parse_list(xml, page=1).entries
    assert len(entries) == 1
    assert entries[0].key == "msrc:2026-41108"
    assert entries[0].embedded_detail["rss_revision"] == "2.0"
    assert entries[0].embedded_detail["updated_at"] == "2026-11-24T01:00:00+00:00"
    assert "published_at" not in entries[0].embedded_detail


@pytest.mark.parametrize("key,url", [
    ("paloalto", "https://security.paloaltonetworks.com.evil.example/CVE-2026-12345"),
    ("msrc", "https://evil.example/update-guide/vulnerability/CVE-2026-12345"),
    ("huawei_sa", "https://evil.example/en/psirt/security-advisories/2026/huawei-sa-example"),
    ("zimbra", "https://evil.example/index.php?title=Zimbra_Releases/10.1.21&diff=71512"),
])
def test_rss_cannot_redirect_discovery_to_an_untrusted_host(key, url):
    with pytest.raises(ValueError):
        get_provider(key).parse_list(rss([item("CVE-2026-12345", url)]), page=1)


def test_zimbra_uses_the_latest_wiki_revision_for_each_patch():
    provider = get_provider("zimbra")
    release = "https://wiki.zimbra.com/index.php?title=Zimbra_Releases/10.1.20"
    other_edit = item("General Wiki edit", "https://wiki.zimbra.com/index.php?title=Help&diff=71513")
    xml = rss([
        other_edit,
        item("Zimbra Releases/10.1.20", release + "&diff=71490", date="Mon, 23 Nov 2026 01:00:00 GMT"),
        item("Zimbra Releases/10.1.20", release + "&diff=71512&oldid=71490"),
        item("Legacy patch", "https://wiki.zimbra.com/index.php?title=Zimbra_Releases%2F8.8.15%2FP47&diff=71511"),
        item("Install guide", "https://wiki.zimbra.com/index.php?title=Zimbra_Releases/10.1.0/patch_installation"),
        item("Untrusted link", "https://evil.example/wiki/Zimbra_Releases/99.0.0"),
    ])
    entries = provider.parse_list(xml, page=1).entries
    assert [entry.key for entry in entries] == ["zimbra:10.1.20", "zimbra:8.8.15/P47"]
    assert entries[0].embedded_detail["updated_at"] == "2026-11-24T01:00:00+00:00"
    assert entries[0].disclosure_date is None
    assert provider.parse_list(rss([other_edit]), page=1).exhausted


def test_huawei_reports_stale_feed_and_retains_full_article_dates(caplog):
    provider = get_provider("huawei_sa")
    url = "https://www.huawei.com/en/psirt/security-advisories/2026/huawei-sa-example-en"
    entry = provider.parse_list(rss([item("Huawei advisory", url, date="Fri, 01 Jan 2010 00:00:00 GMT")]), page=1).entries[0]
    assert "RSS coverage may be stale" in caplog.text
    assert provider.detail_url_for_entry(entry) == url
    assert provider.detail_url_for_entry(restore_entry(retry_entry_data(entry))) == url
    detail = provider.parse_detail((HUAWEI / "detail.html").read_text()).to_dict()
    document = build_mongo_document(entry.to_record(detail, detail_url=url), {"scraped_at":NOW.isoformat()})
    assert document["published_at"] == datetime(2026, 5, 31, 16, tzinfo=UTC)
    assert document["updated_at"] == document["published_at"]
    assert document["severity"] == "High"
    assert "Complete kernel issue" in document["details"]["content"]
    assert "Navigation excluded" not in document["details"]["content"]


class MSRCClient(FakeMSRCClient):
    def __init__(self):
        super().__init__()
        self.feed = msrc_feed("CVE-2026-41108", "CVE-2026-50001")
        self.fail_month = False
        self.omit_cve = False
        self.bad_document_host = False

    async def get_html(self, url):
        assert url == get_provider("msrc").list_url(1)
        self.urls_seen.append(url)
        return FetchResult(html=self.feed, status_code=200, url=url)

    async def get_json(self, url, *, headers=None):
        if "/cvrf/2026-Jun" in url and self.fail_month:
            raise FetchError("Monthly document unavailable", status_code=503)
        result = await super().get_json(url, headers=headers)
        if self.bad_document_host and "/Updates/" in url:
            result.data["value"][0]["CvrfUrl"] = "https://evil.example/cvrf/v3.0/cvrf/2026-Jun"
        if self.omit_cve and "/cvrf/2026-Jun" in url:
            result.data["Vulnerability"] = []
        return result


def sync(tmp_path, provider, client, collection, *, limit=1000, minute=0):
    from vuln_scraper.runner import ScraperRunner
    settings = ScraperSettings(data_dir=tmp_path, mongo_enabled=True, mongo_config_file=None,
                               mongo_collection="news", mongo_conflict="overwrite", scrapers_config_file=None,
                               request_delay=0, retries=0, concurrency=1, limit=limit)
    runner = ScraperRunner(settings, provider=provider, mongo_client_factory=fake_mongo_factory(collection),
                           sync_context=SyncContext(until=NOW+timedelta(minutes=minute), max_pages=1, batch_size=1))
    return asyncio.run(runner._run_with_client(client))


def test_msrc_only_stores_cves_named_by_rss_with_full_details_and_precise_update_date(tmp_path):
    client, collection = MSRCClient(), FakeMongoCollection()
    client.feed = msrc_feed("CVE-2026-41108")
    output = sync(tmp_path, get_provider("msrc"), client, collection)
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {"msrc:2026-41108"}
    document = collection.documents["msrc:2026-41108"]
    assert document["updated_at"] == datetime(2026, 11, 24, 1, tzinfo=UTC)
    assert document["published_at"] < datetime(2026, 7, 1, tzinfo=UTC)
    assert document["details"]["remediations"]
    assert "_list_summary" not in document["details"]
    assert all(not url.endswith('/Updates') for url in client.urls_seen)


def test_msrc_resume_limit_month_cache_and_unchanged_reconciliation(tmp_path):
    client, collection = MSRCClient(), FakeMongoCollection()
    first = sync(tmp_path, get_provider("msrc"), client, collection, limit=1)
    assert first["sync"]["incremental_status"] == "partial"
    second = sync(tmp_path, get_provider("msrc"), client, collection, limit=1, minute=1)
    assert second["sync"]["incremental_status"] == "up_to_date"
    assert len(collection.documents) == 2
    client.urls_seen.clear()
    unchanged = sync(tmp_path, get_provider("msrc"), client, collection, minute=2)
    assert unchanged["mongo_sync"]["inserted"] == unchanged["mongo_sync"]["overwritten"] == 0
    assert unchanged["mongo_sync"]["unchanged"] == 2
    assert sum('/cvrf/2026-Jun' in url for url in client.urls_seen) == 1


@pytest.mark.parametrize("problem", ["fail_month", "omit_cve", "bad_document_host"])
def test_msrc_detail_failures_preserve_full_records_and_recover(tmp_path, problem):
    client, collection = MSRCClient(), FakeMongoCollection()
    sync(tmp_path, get_provider("msrc"), client, collection)
    before = copy.deepcopy(collection.documents)
    setattr(client, problem, True)
    failed = sync(tmp_path, get_provider("msrc"), client, collection, minute=1)
    assert failed["sync"]["pending_retries"] == 2
    assert collection.documents == before
    assert not any('evil.example' in url for url in client.urls_seen)
    setattr(client, problem, False)
    for path in (tmp_path / "sync-cache/msrc").glob('*.json'):
        path.unlink()
    recovered = sync(tmp_path, get_provider("msrc"), client, collection, minute=2)
    assert recovered["sync"]["pending_retries"] == 0
    assert len(collection.documents) == 2


@pytest.mark.parametrize("key", ["paloalto", "msrc", "huawei_sa", "zimbra"])
def test_feed_failure_never_falls_back_to_old_listings(tmp_path, key):
    class Client:
        urls = []
        async def get_html(self, url):
            self.urls.append(url)
            return FetchResult(html='<html>Unavailable</html>', status_code=200, url=url)
    provider, client, collection = get_provider(key), Client(), FakeMongoCollection()
    output = sync(tmp_path, provider, client, collection)
    assert client.urls == [provider.list_url(1)]
    assert output["sync"]["incremental_status"] == "error"
    assert not collection.documents


@pytest.mark.parametrize("key", ["paloalto", "huawei_sa"])
def test_current_feed_timestamp_cannot_republish_an_old_article(tmp_path, key):
    provider = get_provider(key)
    if key == "paloalto":
        url = 'https://security.paloaltonetworks.com/CVE-2026-0265'
        feed = rss([item('CVE-2026-0265 Advisory', url)])
        detail = paloalto_detail_html('CVE-2026-0265')
    else:
        url = 'https://www.huawei.com/en/psirt/security-advisories/2026/huawei-sa-example-en'
        feed = rss([item('Huawei advisory', url)])
        detail = (HUAWEI / 'detail.html').read_text()
    class Client:
        async def get_html(self, requested):
            assert requested in {provider.list_url(1), url}
            return FetchResult(html=feed if requested==provider.list_url(1) else detail, status_code=200, url=requested)
    collection = FakeMongoCollection()
    output = sync(tmp_path, provider, Client(), collection)
    assert output["sync"]["outside_window"] == 1
    assert output["mongo_sync"]["inserted"] == 0
    assert not collection.documents


def test_zimbra_scrapes_current_rss_revisions_with_original_release_dates(tmp_path):
    provider = get_provider("zimbra")
    release_url = "https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20"
    revision_url = "https://wiki.zimbra.com/index.php?title=Zimbra_Releases/10.1.20&diff=71512"

    class Client:
        def __init__(self):
            self.date = "Mon, 23 Nov 2026 01:00:00 GMT"
            self.urls = []

        async def get_html(self, url):
            self.urls.append(url)
            if url == provider.list_url(1):
                html = rss([item("Zimbra Releases/10.1.20", revision_url, date=self.date)])
            else:
                assert url == release_url
                html = ZIMBRA_DETAIL
            return FetchResult(html=html, status_code=200, url=url)

    collection, client = FakeMongoCollection(), Client()
    old = sync(tmp_path, provider, client, collection)
    assert old["sync"]["outside_window"] == 1
    assert not collection.documents
    assert client.urls == [provider.list_url(1)]

    client.date = "Tue, 24 Nov 2026 01:00:00 GMT"
    current = sync(tmp_path, provider, client, collection, minute=1)
    assert current["mongo_sync"]["inserted"] == 1
    document = collection.documents["zimbra:10.1.20"]
    assert document["published_at"] == datetime(2026, 7, 19, 16, tzinfo=UTC)
    assert document["updated_at"] == datetime(2026, 11, 24, 1, tzinfo=UTC)
    assert document["source"]["detail_url"] == release_url
    assert document["details"]["security_fixes"] == ["Fixed command injection.", "Fixed stored XSS."]

    unchanged = sync(tmp_path, provider, client, collection, minute=2)
    assert unchanged["mongo_sync"]["unchanged"] == 1
    assert unchanged["mongo_sync"]["overwritten"] == 0


def test_zimbra_retains_old_release_publication_but_qualifies_a_real_wiki_edit():
    provider = get_provider('zimbra')
    html = ZIMBRA_DETAIL+'<li id="footer-info-lastmod">This page was last edited on 24 November 2026, at 01:10.</li>'
    detail = provider.parse_detail(html).to_dict()
    assert detail['release_date'] == '2026-07-20'
    assert detail['updated_at'] == '2026-11-24T01:10:00+00:00'


def test_zimbra_accepts_the_live_sept_date_format_and_rejects_invalid_dates():
    provider = get_provider('zimbra')
    detail = provider.parse_detail(ZIMBRA_DETAIL.replace('July 20, 2026', 'Sept 24, 2026'))
    assert detail.release_date == '2026-09-24'
    with pytest.raises(ValueError, match='release date'):
        provider.parse_detail(ZIMBRA_DETAIL.replace('July 20, 2026', 'Unknown 99, 2026'))


def test_switching_discovery_retires_api_cursors_but_keeps_stored_news(tmp_path):
    from vuln_scraper.sync_state import SnapshotCache
    client, collection = MSRCClient(), FakeMongoCollection()
    sync(tmp_path, get_provider('msrc'), client, collection, limit=1)
    states = collection.sync_collections['news_sync_state']
    old = states.documents['msrc']
    assert old['tasks']
    old['discovery_version'] = 'legacy-api'
    # This pending page must not be resumed after discovery switches to RSS.
    cache = SnapshotCache(tmp_path/'sync-cache/msrc')
    data = cache.read(old['tasks'][0]['cache'])
    data['entries'][1]['identity']['code'] = '2026-99999'
    data['entries'][1]['embedded_detail']['detail_url'] = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99999'
    old['tasks'][0]['cache'] = cache.write(data)
    old['tasks'][0]['version'] = 'legacy-api'
    old['tasks'][0]['page'] = 99
    before = set(collection.documents)
    client.urls_seen.clear()
    result = sync(tmp_path, get_provider('msrc'), client, collection, minute=1)
    assert states.documents['msrc']['discovery_version'] == 'rss-v1'
    assert result['sync']['incremental_status'] == 'up_to_date'
    assert before <= set(collection.documents)
    assert len(collection.documents) == 2
    assert all(not url.endswith('/Updates') for url in client.urls_seen)
