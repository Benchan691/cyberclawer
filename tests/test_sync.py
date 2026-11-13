import asyncio
import copy
import io
import zipfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import FetchError, JSONFetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers.cve.provider import CVEProvider
from vuln_scraper.scrapers.fortiguard.provider import FortiguardProvider
from vuln_scraper.scrapers.github_advisory.provider import GitHubAdvisoryProvider
from vuln_scraper.scrapers.govcert.provider import GovCERTProvider
from vuln_scraper.scrapers.msrc.provider import MSRCProvider
from vuln_scraper.scrapers.nvd.provider import NvdProvider
from vuln_scraper.scrapers.splunk.provider import SplunkProvider
from vuln_scraper.sync_archive import baseline_page
from vuln_scraper.sync_state import SyncContext, SyncStateStore, catch_up_lock

NOW = datetime(2026, 11, 13, 9, 30, tzinfo=UTC)


def entry(number, provider="fortiguard", *, old=True):
    code = f"FG-IR-26-{number:03}" if provider == "fortiguard" else str(number)
    if provider == "splunk":
        code = f"SVD-2611-{number:03}"
    return ListEntry(VulnerabilityId(provider.upper(), code), f"Advisory {number}", None,
        "2026-01-01" if old else "2026-11-13", None, provider, "https://example.test",
        {"title": f"Advisory {number}", "advisory_id": code, "published_date": "2026-01-01",
         "updated_date": "2026-01-01", "content": f"Full advisory {number}"})


class Harness:
    def __init__(self, directory, provider=None):
        self.directory = directory
        self.provider = provider or FortiguardProvider()
        self.news = FakeMongoCollection()
        self.calls = []
        self.pages = lambda context, page: ListPage(page, [entry(i) for i in range(1, 6)], total_pages=1)

    @property
    def states(self):
        return self.news.sync_collections["news_sync_state"]

    def run(self, *, limit=1000, max_pages=100, batch_size=5, now=NOW, configure=None):
        settings = ScraperSettings(data_dir=self.directory, request_delay=0, retries=0,
            scrapers_config_file=None, mongo_config_file=None, mongo_enabled=True,
            mongo_conflict="overwrite", limit=limit, mongo_collection="news")
        runner = ScraperRunner(settings, provider=self.provider,
            mongo_client_factory=fake_mongo_factory(self.news),
            sync_context=SyncContext(until=now, max_pages=max_pages, batch_size=batch_size))

        async def fetch(client, url, page):
            self.calls.append((runner._active_sync_context, page))
            return copy.deepcopy(self.pages(runner._active_sync_context, page))

        runner._fetch_list_page = fetch
        if configure:
            configure(runner)
        return asyncio.run(runner._run_with_client(object()))


def test_bootstrap_prefers_updated_and_interprets_bson_dates_as_utc():
    news = FakeMongoCollection({
        "fortiguard:old": {"_id": "fortiguard:old", "source": {"provider": "fortiguard"},
            "updated_at": datetime(2026, 11, 10, 16), "published_at": datetime(2026, 11, 12)},
    })
    store = SyncStateStore(FakeMongoCollection(), "fortiguard")
    state = store.load(news, NOW)
    assert state["last_successful_until"] == "2026-11-10T16:00:00+00:00"
    assert not state["bootstrap_empty"]


def test_completed_position_does_not_jump_over_an_unfinished_window():
    store = SyncStateStore(FakeMongoCollection(), "fortiguard")
    state = store.load(FakeMongoCollection(), NOW)
    start = datetime.fromisoformat(state["last_successful_until"])
    store.advance(state, {"since": (start + timedelta(days=1)).isoformat(),
                          "until": (start + timedelta(days=2)).isoformat()}, complete=True)
    assert state["last_successful_until"] == start.isoformat()
    store.advance(state, {"since": start.isoformat(),
                          "until": (start + timedelta(days=1)).isoformat()}, complete=True)
    assert state["last_successful_until"] == (start + timedelta(days=2)).isoformat()


def test_fixed_windows_resume_from_saved_progress_instead_of_midnight(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.news.documents["nvd:old"] = {"_id": "nvd:old", "source": {"provider": "nvd"},
                                    "updated_at": NOW - timedelta(days=3)}
    h.pages = lambda context, page: ListPage(page, [entry(1, "nvd")], total_pages=1)
    first = h.run()
    assert h.calls[0][0].since == NOW - timedelta(days=4)
    assert h.calls[0][0].until == NOW
    assert first["mongo_sync"]["inserted"] == 1
    assert first["sync"]["last_successful_until"] == NOW.isoformat()
    h.calls.clear()
    h.run(now=NOW + timedelta(hours=18))
    assert h.calls[0][0].since == NOW - timedelta(days=1)
    assert h.calls[0][0].until == NOW + timedelta(hours=18)


def test_identical_snapshot_resumes_past_limit_without_starving_tail(tmp_path):
    h = Harness(tmp_path)
    outputs = [h.run(limit=2, now=NOW + timedelta(hours=i)) for i in range(3)]
    assert len(h.news.documents) == 5
    assert all(output["sync"]["checked"] <= 2 for output in outputs)
    assert outputs[-1]["sync"]["incremental_status"] == "up_to_date"
    assert sum(output["mongo_sync"]["inserted"] for output in outputs) == 5


def test_mongo_error_is_retried_and_blocks_success_position(tmp_path):
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [entry(1), entry(2)], total_pages=1)
    h.news.fail_insert_once_for = entry(1).key
    first = h.run()
    assert first["mongo_sync"]["inserted"] == 1
    assert first["sync"]["pending_retries"] == 1
    assert first["sync"]["last_successful_until"] != NOW.isoformat()
    second = h.run(now=NOW + timedelta(hours=1))
    assert len(h.news.documents) == 2
    assert second["sync"]["pending_retries"] == 0
    assert second["sync"]["last_successful_until"] == (NOW + timedelta(hours=1)).isoformat()


def test_archive_continues_after_an_old_known_head_page(tmp_path):
    h = Harness(tmp_path, GovCERTProvider())
    h.pages = lambda context, page: ListPage(page, [entry(page, "govcert")], total_pages=3)
    first = h.run(limit=10, max_pages=2)
    assert len(h.calls) == 2
    assert {"govcert:1", "govcert:2"} <= set(h.news.documents)
    assert first["sync"]["archive_cursor"] is not None
    h.run(limit=10, max_pages=3, now=NOW + timedelta(hours=1))
    assert "govcert:3" in h.news.documents


def test_list_failure_keeps_window_pending_but_next_run_can_recover(tmp_path):
    h = Harness(tmp_path)

    def unavailable(context, page):
        raise FetchError("Service unavailable")

    h.pages = unavailable
    first = h.run()
    assert first["stop_reason"] == "error"
    assert first["sync"]["pending_windows"] == 1
    assert first["sync"]["last_successful_until"] < NOW.isoformat()
    h.pages = lambda context, page: ListPage(page, [entry(1)], total_pages=1)
    second = h.run(now=NOW + timedelta(hours=1))
    assert second["mongo_sync"]["inserted"] == 1
    assert second["sync"]["pending_windows"] == 0


def test_monthly_children_resume_across_limits_without_reexpanding(tmp_path):
    h = Harness(tmp_path, MSRCProvider())
    parent = entry(1, "msrc")
    parent.embedded_detail["_list_summary"] = True
    h.pages = lambda context, page: ListPage(page, [parent], total_pages=1)
    details = []

    def configure(runner):
        async def fetch(client, value):
            details.append(value.key)
            records = [entry(i, "msrc").to_record() for i in range(1, 6)]
            ids = [f"msrc:{record['code']}" for record in records]
            runner.records_by_id.update(zip(ids, records))
            runner.expanded_entry_ids[value.key] = ids
        runner._scrape_detail = fetch

    for i in range(3):
        h.run(limit=2, now=NOW + timedelta(hours=i), configure=configure)
    assert len(h.news.documents) == 5
    assert len(details) == 1


def test_cache_loss_replays_uncommitted_work_without_losing_advisories(tmp_path):
    h = Harness(tmp_path)
    h.run(limit=2)
    for path in (tmp_path / "sync-cache" / "fortiguard").glob("*.json"):
        path.unlink()
    for i in range(1, 4):
        h.run(limit=2, now=NOW + timedelta(hours=i))
    assert len(h.news.documents) == 5


def test_manifest_filtering_does_not_shift_saved_candidate_offsets(tmp_path):
    h = Harness(tmp_path, SplunkProvider())
    h.pages = lambda context, page: ListPage(page, [entry(i, "splunk") for i in range(1, 6)], total_pages=1)
    for i in range(3):
        h.run(limit=2, now=NOW + timedelta(hours=i))
    assert len(h.news.documents) == 5


def test_limit_on_listing_requests_still_allows_saved_pages_to_resume(tmp_path):
    h = Harness(tmp_path)
    h.run(limit=2, max_pages=1)
    second = h.run(limit=2, max_pages=1, now=NOW + timedelta(hours=1))
    assert second["sync"]["listing_requests"] == 1
    assert len(h.news.documents) == 4


def test_latest_head_continues_while_an_older_failure_remains_pending(tmp_path):
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [entry(1)], total_pages=1)
    h.news.fail_insert_once_for = entry(1).key
    first = h.run()
    old_position = first["sync"]["last_successful_until"]
    h.news.fail_insert_once_for = entry(1).key
    h.pages = lambda context, page: ListPage(page, [entry(2)], total_pages=1)
    second = h.run(now=NOW + timedelta(hours=1))
    assert entry(2).key in h.news.documents
    assert second["sync"]["last_successful_until"] == old_position
    assert second["sync"]["pending_retries"] == 1


def test_retries_survive_missing_cached_payloads(tmp_path):
    h = Harness(tmp_path)
    failed = entry(1)
    failed.embedded_detail["_list_summary"] = True
    h.pages = lambda context, page: ListPage(page, [failed], total_pages=1)
    attempts = []

    def configure(runner):
        async def detail(client, value):
            attempts.append(value.key)
            if len(attempts) == 1:
                runner._record_failure(value, "https://example.test/detail", "HTTP 503", phase="detail")
            else:
                runner.records_by_id[value.key] = entry(1).to_record()
        runner._scrape_detail = detail

    first = h.run(configure=configure)
    assert first["sync"]["pending_retries"] == 1
    for path in (tmp_path / "sync-cache" / "fortiguard").glob("*.json"):
        path.unlink()
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True)
    second = h.run(now=NOW + timedelta(hours=1), configure=configure)
    assert second["sync"]["pending_retries"] == 0
    assert entry(1).key in h.news.documents


def test_unacknowledged_insert_does_not_commit_sync_success(tmp_path):
    from types import SimpleNamespace
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [entry(1)], total_pages=1)
    h.news.insert_one = lambda document: SimpleNamespace(acknowledged=False)
    output = h.run()
    assert output["sync"]["pending_retries"] == 1
    assert output["sync"]["last_successful_until"] != NOW.isoformat()


def test_cve_history_gap_runs_a_baseline_without_claiming_early_completion(tmp_path, monkeypatch):
    h = Harness(tmp_path, CVEProvider())
    h.news.documents["cve:old"] = {"_id": "cve:old", "source": {"provider": "cve"},
                                    "updated_at": NOW - timedelta(days=100)}
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True,
                                             coverage_start=(NOW - timedelta(days=30)).isoformat())

    async def archive(client, task, directory, provider):
        task["asset"] = {"url": "https://example.test/baseline"}
        task["until"] = NOW.replace(hour=0, minute=0).isoformat()
        return ListPage(page=task["page"], entries=[], total_pages=2 if task["page"] == 1 else 2,
                        exhausted=task["page"] == 2)

    monkeypatch.setattr("vuln_scraper.sync_engine.baseline_page", archive)
    first = h.run(max_pages=2)
    assert first["sync"]["history_status"] == "recovering"
    assert first["sync"]["incremental_status"] == "partial"
    assert first["sync"]["last_successful_until"] != NOW.isoformat()
    second = h.run(max_pages=5, now=NOW + timedelta(hours=1))
    assert second["sync"]["history_status"] == "idle"
    assert second["sync"]["last_successful_until"] == (NOW + timedelta(hours=1)).isoformat()


def test_empty_unverified_page_never_advances_progress(tmp_path):
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [], total_pages=1)
    first = h.run()
    assert first["stop_reason"] == "error"
    assert first["sync"]["last_successful_until"] != NOW.isoformat()


def test_two_process_locks_cannot_enter_and_release_after_exception(tmp_path):
    with pytest.raises(RuntimeError):
        with catch_up_lock(tmp_path) as acquired:
            assert acquired
            with catch_up_lock(tmp_path) as second:
                assert not second
            raise RuntimeError("interrupted")
    with catch_up_lock(tmp_path) as acquired:
        assert acquired


def test_github_uses_modified_range_and_link_cursor():
    provider = GitHubAdvisoryProvider()
    context = SyncContext(since=NOW - timedelta(days=1), until=NOW)
    request = parse_qs(urlparse(provider.sync_list_url(context, 1)).query)
    assert request["sort"] == ["updated"]
    assert request["modified"] == [f"{context.since.isoformat()}..{NOW.isoformat()}"]
    link = "https://api.github.com/advisories?after=next&sort=updated"
    parsed = provider.parse_sync_list([], page=1, context=context, headers={"link": f'<{link}>; rel="next"'})
    assert parsed.next_cursor == link
    assert provider.sync_list_url(replace(context, cursor=link), 2) == link
    with pytest.raises(ValueError):
        provider.sync_list_url(replace(context, cursor="https://example.test/advisories"), 2)
    with pytest.raises(ValueError, match="identity"):
        provider.parse_sync_list([{"message": "not an advisory"}], page=1, context=context, headers={})


def test_nvd_long_outage_is_split_and_windows_stay_fixed(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.news.documents["nvd:old"] = {"_id": "nvd:old", "source": {"provider": "nvd"},
                                    "updated_at": NOW - timedelta(days=300)}
    h.pages = lambda context, page: ListPage(page, [], total_pages=0, exhausted=True)
    h.run()
    assert len(h.calls) == 3
    for context, page in h.calls:
        assert context.until - context.since <= timedelta(days=120)
        query = parse_qs(urlparse(h.provider.sync_list_url(context, page)).query)
        assert query["lastModStartDate"] == [context.since.isoformat(timespec="milliseconds")]


def test_cve_uses_batch_arrival_time_for_backdated_records():
    provider = CVEProvider()
    payload = [{"fetchTime": NOW.isoformat(), "new": [{"cveId": "CVE-2026-1234",
        "dateUpdated": "2020-01-01T00:00:00Z", "githubLink": provider.cve_url("2026-1234")}]}]
    parsed = provider.parse_sync_list(payload, page=1,
        context=SyncContext(since=NOW - timedelta(hours=1), until=NOW), headers={})
    assert len(parsed.entries) == 1
    assert parsed.entries[0].disclosure_date == "2020-01-01T00:00:00Z"


def test_baseline_manifest_is_pinned_and_fetches_current_record_urls(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zipped:
        zipped.writestr("cves/2026/1xxx/CVE-2026-1234.json", "{}")
        zipped.writestr("../CVE-2025-9999.json", "{}")
    url = "https://github.com/CVEProject/cvelistV5/releases/download/test/2026-11-13_all_CVEs_at_midnight.zip"

    class Client:
        async def get_json(self, target):
            return JSONFetchResult([{"assets": [{"name": "2026-11-13_all_CVEs_at_midnight.zip",
                "id": 123, "browser_download_url": url}]}], 200, target)

        async def download(self, target, path):
            path.write_bytes(data.getvalue())

    task = {"page": 1}
    parsed = asyncio.run(baseline_page(Client(), task, tmp_path, CVEProvider()))
    assert len(parsed.entries) == 2
    assert all(item.embedded_detail["_github_link"].startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/") for item in parsed.entries)
    assert task["until"] == "2026-11-13T00:00:00+00:00"
    assert not (tmp_path.parent / "CVE-2025-9999.json").exists()
