"""All operational scrapers share the same publication/update date boundary."""
from datetime import UTC, datetime, timedelta

import pytest

from tests.test_sync import Harness, NOW, entry
from vuln_scraper.models import ListPage, VulnerabilityId
from vuln_scraper.scrapers import get_provider, provider_keys
from vuln_scraper.scrapers.msrc.provider import MSRCProvider
from vuln_scraper.scrapers.nvd.provider import NvdProvider
from vuln_scraper.timestamps import publication_time, source_news_time


def advisory(number, provider, *, published="2026-11-13", updated=None, summary=False):
    value = entry(number, provider)
    code = value.identity.code
    if provider in {"cve", "msrc"}:
        code = f"2026-{10000 + number}"
    elif provider == "bleepingcomputer":
        code = f"security/advisory-{number}"
    elif provider == "the_hacker_news":
        code = f"2026-11-advisory-{number}"
    elif provider == "wiz":
        code = f"11111111-2222-4333-8444-{number:012d}"
    elif provider == "github_advisory":
        code = f"GHSA-aaaa-bbbb-{number:04d}"
    value.identity = VulnerabilityId("THN" if provider == "the_hacker_news" else provider.upper(), code)
    updated = published if updated is None else updated
    value.disclosure_date = published
    value.embedded_detail.update({"advisory_id": code, "published_at": published,
        "published_date": published, "initial_release_date": published,
        "updated_at": updated, "updated_date": updated,
        "current_release_date": updated})
    if summary:
        value.embedded_detail["_list_summary"] = True
    return value


@pytest.mark.parametrize("provider", provider_keys())
def test_every_provider_rejects_old_unchanged_news(tmp_path, provider):
    h = Harness(tmp_path, get_provider(provider))
    old = advisory(1, provider, published="2026-11-12", summary=provider != "msrc")
    recent = advisory(2, provider, summary=True)
    h.pages = lambda context, page: ListPage(page, [old, recent], total_pages=1)
    fetched = []

    def configure(runner):
        async def detail(client, value):
            fetched.append(value.key)
            record = advisory(2, provider).to_record()
            runner.records_by_id[value.key] = record
            if provider == "msrc":
                runner.expanded_entry_ids[value.key] = [value.key]
        runner._scrape_detail = detail

    output = h.run(limit=1, configure=configure)
    assert fetched == [recent.key]
    assert set(h.news.documents) == {recent.key}
    assert output["mongo_sync"]["errors"] == []
    assert output["sync"]["outside_window"] == 1


@pytest.mark.parametrize("provider", provider_keys())
def test_every_provider_accepts_an_old_article_with_an_update_today(tmp_path, provider):
    h = Harness(tmp_path, get_provider(provider))
    updated = advisory(1, provider, published="2020-01-01", updated=NOW.isoformat())
    h.pages = lambda context, page: ListPage(page, [updated], total_pages=1)
    output = h.run()
    assert set(h.news.documents) == {updated.key}
    assert output["mongo_sync"]["errors"] == []


def test_hong_kong_midnight_is_inclusive_and_tomorrow_is_excluded(tmp_path):
    h = Harness(tmp_path)
    values = [advisory(1, "fortiguard", published="2026-11-12T15:59:59Z"),
              advisory(2, "fortiguard", published="2026-11-12T16:00:00Z"),
              advisory(3, "fortiguard", published="2026-11-13T16:00:00Z")]
    h.pages = lambda context, page: ListPage(page, values, total_pages=1)
    output = h.run()
    assert set(h.news.documents) == {values[1].key}
    assert output["sync"]["outside_window"] == 2


def test_nvd_utc_updates_on_previous_calendar_date_are_today_in_hong_kong(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    payload = {"totalResults":3, "resultsPerPage":3, "startIndex":0,
        "vulnerabilities":[{"cve":{"id":f"CVE-2026-{10000 + index}",
            "published":"2020-01-01T00:00:00.000", "lastModified":modified,
            "descriptions":[{"lang":"en","value":str(index)}]}}
            for index, modified in enumerate(["2026-11-12T15:59:59.999",
                "2026-11-12T16:00:00.000", "2026-11-13T16:00:00.000"])]}
    h.pages = lambda context, page: h.provider.parse_list(payload, page=page)
    output = h.run()
    assert output["mongo_sync"]["inserted"] == 1
    record = next(iter(h.news.documents.values()))
    assert record["title"] == "1"
    assert record["updated_at"] == datetime(2026, 11, 12, 16, tzinfo=UTC)


def test_explicit_days_option_uses_a_bounded_calendar_window(tmp_path):
    h = Harness(tmp_path)
    old = advisory(1, "fortiguard", published="2026-11-12")
    h.pages = lambda context, page: ListPage(page, [old], total_pages=1)
    assert h.run()["mongo_sync"]["inserted"] == 0
    assert h.run(days=2, now=NOW + timedelta(hours=1))["mongo_sync"]["inserted"] == 1


def test_detail_publication_is_checked_before_storage_and_unknown_is_not_today(tmp_path):
    h = Harness(tmp_path)
    recent_hint = advisory(1, "fortiguard", summary=True)
    h.pages = lambda context, page: ListPage(page, [recent_hint], total_pages=1)

    def configure(runner):
        async def detail(client, value):
            runner.records_by_id[value.key] = advisory(1, "fortiguard", published=None).to_record()
        runner._scrape_detail = detail

    output = h.run(configure=configure)
    assert not h.news.documents
    assert output["sync"]["outside_window"] == 1


@pytest.mark.parametrize("cache_missing", [False, True])
def test_previous_days_snapshots_and_retries_expire_without_rewriting_news(tmp_path, cache_missing):
    h = Harness(tmp_path)
    values = [advisory(1, "fortiguard"), advisory(2, "fortiguard")]
    h.pages = lambda context, page: ListPage(page, values, total_pages=1)
    h.news.fail_insert_once_for = values[0].key
    assert h.run()["sync"]["pending_retries"] == 1
    if cache_missing:
        for path in (tmp_path / "sync-cache" / "fortiguard").glob("*.json"):
            path.unlink()
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True)
    output = h.run(now=NOW + timedelta(days=1))
    assert set(h.news.documents) == {values[1].key}
    assert output["sync"]["pending_retries"] == 0
    assert output["sync"]["pending_windows"] == 0
    assert output["sync"]["incremental_status"] == "up_to_date"


def test_expanded_monthly_records_filter_old_children_and_keep_resume_offsets(tmp_path):
    h = Harness(tmp_path, MSRCProvider())
    parent = advisory(1, "msrc", published="2026-01-01", updated=NOW.isoformat(), summary=True)
    h.pages = lambda context, page: ListPage(page, [parent], total_pages=1)
    fetched = []
    children = [advisory(2, "msrc", published="2026-01-01"),
                advisory(3, "msrc"), advisory(4, "msrc"),
                advisory(5, "msrc", published=None)]

    def configure(runner):
        async def detail(client, value):
            fetched.append(value.key)
            for child in children:
                runner.records_by_id[child.key] = child.to_record()
            runner.expanded_entry_ids[value.key] = [child.key for child in children]
        runner._scrape_detail = detail

    outputs = [h.run(limit=1, now=NOW + timedelta(hours=i), configure=configure) for i in range(4)]
    assert set(h.news.documents) == {children[1].key, children[2].key}
    assert fetched == [parent.key]
    assert outputs[-1]["sync"]["incremental_status"] == "up_to_date"


def test_legacy_modification_dates_are_not_used_as_publication_evidence():
    for provider in ("cve", "msrc", "qianxin"):
        assert publication_time({"type": provider, "disclosure_date": NOW.isoformat()}) is None
        assert source_news_time({"type": provider, "disclosure_date": NOW.isoformat()}) == NOW
    assert publication_time({"type":"hpe", "details":{"hpe":{"published_at":"2026-11-12T16:00:00Z"}}}) == datetime(2026, 11, 12, 16, tzinfo=UTC)
    assert source_news_time({"type":"wiz", "observed_at":NOW, "scraped_at":NOW.isoformat()}) is None


def test_retry_keeps_the_precise_feed_date_at_the_hong_kong_boundary(tmp_path):
    h = Harness(tmp_path, get_provider("wiz"))
    recent = advisory(1, "wiz", published="2026-11-12T16:00:00Z", summary=True)
    recent.disclosure_date = "2026-11-12"
    h.pages = lambda context, page: ListPage(page, [recent], total_pages=1)
    attempts = []

    def configure(runner):
        async def detail(client, value):
            attempts.append(value.key)
            if len(attempts) == 1:
                runner._record_failure(value, "https://threats.wiz.io/article", "HTTP 503", phase="detail")
            else:
                runner.records_by_id[value.key] = advisory(1, "wiz", published="2026-11-12T16:00:00Z").to_record()
        runner._scrape_detail = detail

    assert h.run(configure=configure)["sync"]["pending_retries"] == 1
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True)
    output = h.run(now=NOW + timedelta(hours=1), configure=configure)
    assert set(h.news.documents) == {recent.key}
    assert len(attempts) == 2
    assert output["sync"]["pending_retries"] == 0
