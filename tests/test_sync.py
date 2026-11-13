import asyncio
import copy
import io
import json
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
        {"title": f"Advisory {number}", "advisory_id": code,
         "published_date": "2026-01-01" if old else "2026-11-13",
         "updated_date": "2026-01-01" if old else "2026-11-13", "content": f"Full advisory {number}"})


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


def test_empty_provider_bootstraps_exactly_seven_days_then_uses_overlap(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.pages = lambda context, page: ListPage(page, [], total_pages=0, exhausted=True)
    h.run()
    assert h.calls[0][0].since == NOW - timedelta(days=7)
    h.calls.clear()
    h.run(now=NOW + timedelta(hours=1))
    assert h.calls[0][0].since == NOW - timedelta(days=1)


def test_identical_snapshot_resumes_past_limit_without_starving_tail(tmp_path):
    h = Harness(tmp_path)
    outputs = [h.run(limit=2, now=NOW + timedelta(hours=i)) for i in range(3)]
    assert len(h.news.documents) == 5
    assert all(output["sync"]["checked"] <= 2 for output in outputs)
    assert outputs[-1]["sync"]["incremental_status"] == "up_to_date"
    assert sum(output["mongo_sync"]["inserted"] for output in outputs) == 5


def test_source_totals_do_not_inherit_another_providers_legacy_checkpoint(tmp_path):
    h = Harness(tmp_path)
    (tmp_path / "checkpoint.json").write_text(json.dumps({"total_records": 99999}))
    h.pages = lambda context, page: ListPage(page, [entry(i) for i in range(1, 6)], total_pages=1, total_records=5)
    assert h.run(limit=2)["total"] == 5


def test_overlapping_windows_do_not_spend_the_budget_replaying_committed_entries(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.pages = lambda context, page: ListPage(page, [entry(i, "nvd") for i in range(1, 6)], total_pages=1)
    h.run(limit=2)
    h.pages = lambda context, page: ListPage(page, [entry(6, "nvd")] + [entry(i, "nvd") for i in range(1, 6)], total_pages=1)
    second = h.run(limit=2, now=NOW + timedelta(hours=1))
    assert second["sync"]["checked"] == 2
    assert {"nvd:1", "nvd:2", "nvd:3", "nvd:6"} <= set(h.news.documents)


def test_an_older_queued_observation_cannot_suppress_a_newer_revision(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.pages = lambda context, page: ListPage(page, [entry(1, "nvd"), entry(2, "nvd")], total_pages=1)
    h.run(limit=1)
    revised = entry(2, "nvd")
    revised.title = "Revised advisory"
    revised.embedded_detail["content"] = "Revised content, original publication date"
    h.pages = lambda context, page: ListPage(page, [entry(3, "nvd"), revised], total_pages=1)
    h.run(limit=3, now=NOW + timedelta(hours=1))
    assert h.news.documents["nvd:2"]["title"] == "Revised advisory"


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


def test_recent_listing_stops_before_missing_history_without_fetching_old_details(tmp_path):
    h = Harness(tmp_path, GovCERTProvider())
    h.pages = lambda context, page: ListPage(page, [entry(page, "govcert", old=page > 1)], total_pages=3)
    first = h.run(limit=10)
    assert len(h.calls) == 2
    assert set(h.news.documents) == {"govcert:1"}
    assert first["sync"]["outside_window"] == 1
    assert first["sync"]["history_status"] == "disabled"
    assert first["sync"]["archive_cursor"] is None
    assert first["sync"]["incremental_status"] == "up_to_date"
    h.calls.clear()
    h.run(limit=10, now=NOW + timedelta(hours=1))
    assert [page for _, page in h.calls] == [1, 2]
    assert set(h.news.documents) == {"govcert:1"}


def test_listing_revision_to_a_known_old_record_is_still_synced(tmp_path):
    h = Harness(tmp_path, GovCERTProvider())
    advisory = entry(1, "govcert", old=False)
    h.pages = lambda context, page: ListPage(page, [advisory], total_pages=1)
    h.run()
    advisory.disclosure_date = "2026-01-01"
    advisory.embedded_detail["updated_date"] = "2026-01-01"
    advisory.embedded_detail["published_date"] = "2026-01-01"
    advisory.embedded_detail["content"] = "Revised advisory"
    output = h.run(now=NOW + timedelta(hours=1))
    assert output["mongo_sync"]["overwritten"] == 1
    assert h.news.documents["govcert:1"]["details"]["content"] == "Revised advisory"


def test_listing_modification_time_keeps_an_old_publication_in_the_recent_pass(tmp_path):
    from vuln_scraper.scrapers.paloalto.provider import PaloAltoProvider
    h = Harness(tmp_path, PaloAltoProvider())
    revised = entry(1, "paloalto")
    revised.embedded_detail["updated_date"] = NOW.isoformat()
    h.pages = lambda context, page: ListPage(page,
        [revised] if page == 1 else [entry(2, "paloalto")], total_pages=3)
    output = h.run()
    assert [page for _, page in h.calls] == [1, 2]
    assert set(h.news.documents) == {"paloalto:1"}
    assert output["sync"]["incremental_status"] == "up_to_date"


@pytest.mark.parametrize("kind", ["archive", "index_audit", "baseline"])
def test_saved_history_and_its_retries_are_retired_but_recent_failures_resume(tmp_path, kind):
    from vuln_scraper.sync_state import entry_data
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [entry(1)], total_pages=1)
    h.news.fail_insert_once_for = entry(1).key
    assert h.run()["sync"]["pending_retries"] == 1
    state = h.states.documents["fortiguard"]
    state["archive"] = {"id": "old-history", "kind": kind, "page": 67}
    state["tasks"].append({"id": "old-history-task", "kind": kind})
    state["history_gap"] = {"since": "2020-01-01", "oldest_visible": "2021-01-01"}
    store = SyncStateStore(h.states, "fortiguard")
    store.defer(entry(2).key, {"entry": entry_data(entry(2)), "task_id": "old-history"})
    store.defer(entry(3).key, {"entry": entry_data(entry(3)), "task_id": "old-history-task"})
    output = h.run(now=NOW + timedelta(hours=1))
    assert set(h.news.documents) == {entry(1).key}
    assert output["sync"]["pending_retries"] == 0
    assert output["sync"]["incremental_status"] == "up_to_date"
    assert h.states.documents["fortiguard"]["archive"] is None


def test_complete_index_only_fetches_recent_or_changed_entries(tmp_path):
    h = Harness(tmp_path, SplunkProvider())
    modified = entry(2, "splunk")
    modified.embedded_detail["last_modified"] = NOW.isoformat()
    h.pages = lambda context, page: ListPage(page, [entry(1, "splunk"), modified], total_pages=1)
    first = h.run()
    assert set(h.news.documents) == {modified.key}
    assert first["sync"]["outside_window"] == 1
    second = h.run(now=NOW + timedelta(hours=1))
    assert second["mongo_sync"]["inserted"] == 0
    assert second["mongo_sync"]["overwritten"] == 0
    assert second["sync"]["history_status"] == "disabled"
    assert h.states.documents["splunk"]["archive"] is None


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
    parent = entry(1, "msrc", old=False)
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
    h.pages = lambda context, page: ListPage(page, [entry(i, "splunk", old=False) for i in range(1, 6)], total_pages=1)
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


def test_unchanged_listing_metadata_does_not_clear_a_failed_detail_retry(tmp_path):
    h = Harness(tmp_path, GovCERTProvider())
    advisory = entry(1, "govcert", old=False)
    advisory.embedded_detail["_list_summary"] = True
    h.pages = lambda context, page: ListPage(page, [advisory], total_pages=1)
    attempts = []

    def configure(runner):
        async def detail(client, value):
            attempts.append(value.key)
            if len(attempts) == 2:
                runner._record_failure(value, "https://example.test/detail", "HTTP 503", phase="detail")
                return
            complete = entry(1, "govcert")
            complete.embedded_detail["content"] = "Revised body" if len(attempts) > 2 else "Original body"
            runner.records_by_id[value.key] = complete.to_record()
        runner._scrape_detail = detail

    h.run(configure=configure)
    advisory.title = "Updated listing"
    second = h.run(now=NOW + timedelta(hours=1), configure=configure)
    assert second["sync"]["pending_retries"] == 1
    third = h.run(now=NOW + timedelta(hours=2), configure=configure)
    assert third["sync"]["pending_retries"] == 0
    assert h.news.documents["govcert:1"]["details"]["content"] == "Revised body"
    assert len(attempts) == 3


def test_unacknowledged_insert_does_not_commit_sync_success(tmp_path):
    from types import SimpleNamespace
    h = Harness(tmp_path)
    h.pages = lambda context, page: ListPage(page, [entry(1)], total_pages=1)
    h.news.insert_one = lambda document: SimpleNamespace(acknowledged=False)
    output = h.run()
    assert output["sync"]["pending_retries"] == 1
    assert output["sync"]["last_successful_until"] != NOW.isoformat()


def test_cve_history_gap_is_reported_without_requesting_a_baseline(tmp_path, monkeypatch):
    h = Harness(tmp_path, CVEProvider())
    h.news.documents["cve:old"] = {"_id": "cve:old", "source": {"provider": "cve"},
                                    "updated_at": NOW - timedelta(days=100)}
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True,
                                             coverage_start=(NOW - timedelta(days=30)).isoformat())

    async def unavailable(*args, **kwargs):
        pytest.fail("Historical recovery must not request a baseline")

    monkeypatch.setattr("vuln_scraper.sync_archive.baseline_page", unavailable)
    monkeypatch.setattr("vuln_scraper.sync_archive.baseline_asset", unavailable)
    first = h.run(max_pages=1)
    assert first["sync"]["history_status"] == "disabled"
    assert first["sync"]["incremental_status"] == "up_to_date"
    assert first["sync"]["last_successful_until"] == NOW.isoformat()
    assert first["sync"]["history_gap"]["until"] == (NOW - timedelta(days=30)).isoformat()
    second = h.run(max_pages=1, now=NOW + timedelta(hours=1))
    assert second["sync"]["history_status"] == "disabled"
    assert second["sync"]["last_successful_until"] == (NOW + timedelta(hours=1)).isoformat()


def test_cve_migrates_a_previously_shortened_window_without_waiting_for_history(tmp_path):
    h = Harness(tmp_path, CVEProvider())
    h.pages = lambda context, page: ListPage(page, [], total_pages=1, exhausted=True)
    h.run()
    state = h.states.documents["cve"]
    start = NOW - timedelta(days=100)
    earliest = NOW - timedelta(days=30)
    for field in ("last_successful_until", "discovered_until"):
        state[field] = start.isoformat()
    state["scheduled_until"] = (NOW - timedelta(hours=1)).isoformat()
    state["recovery_since"] = start.isoformat()
    state["archive"] = {"id": "old-baseline", "kind": "baseline"}
    state["tasks"] = [{"id": "delta-window", "kind": "window", "since": earliest.isoformat(),
        "until": state["scheduled_until"], "page": 1, "cursor": None, "index": 0,
        "cache": None, "child_cache": None, "child_index": 0, "enumerated": False}]
    output = h.run(now=NOW + timedelta(hours=1))
    assert output["sync"]["last_successful_until"] == (NOW + timedelta(hours=1)).isoformat()
    assert output["sync"]["incremental_status"] == "up_to_date"
    assert "recovery_since" not in h.states.documents["cve"]


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
    assert request["modified"] == [f"{context.since.strftime('%Y-%m-%dT%H:%M:%SZ')}..{NOW.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
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


def test_legacy_failed_nvd_window_is_included_in_the_first_resumable_run(tmp_path):
    h = Harness(tmp_path, NvdProvider())
    h.news.documents["nvd:old"] = {"_id": "nvd:old", "source": {"provider": "nvd"},
                                    "updated_at": NOW - timedelta(days=1)}
    old = SyncContext(since=NOW - timedelta(days=50), until=NOW - timedelta(days=5))
    (tmp_path / "checkpoint.json").write_text(json.dumps({"failed": [{
        "identity": "nvd:LIST", "phase": "list", "url": h.provider.sync_list_url(old, 20),
        "error": "Connection cancelled for deployment",
    }]}))
    h.pages = lambda context, page: ListPage(page, [], total_pages=0, exhausted=True)
    h.run()
    assert min(context.since for context, _ in h.calls) <= old.since
    assert max(context.until for context, _ in h.calls) >= old.until


def test_cve_uses_batch_arrival_time_for_backdated_records():
    provider = CVEProvider()
    payload = [{"fetchTime": NOW.isoformat(), "new": [{"cveId": "CVE-2026-1234",
        "dateUpdated": "2020-01-01T00:00:00Z", "githubLink": provider.cve_url("2026-1234")}]}]
    parsed = provider.parse_sync_list(payload, page=1,
        context=SyncContext(since=NOW - timedelta(hours=1), until=NOW), headers={})
    assert len(parsed.entries) == 1
    assert parsed.entries[0].disclosure_date == "2020-01-01T00:00:00Z"


@pytest.mark.parametrize("nested", [False, True])
def test_baseline_manifest_is_pinned_and_fetches_current_record_urls(tmp_path, nested):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zipped:
        zipped.writestr("cves/2026/1xxx/CVE-2026-1234.json", "{}")
        zipped.writestr("../CVE-2025-9999.json", "{}")
    name = "2026-11-13_all_CVEs_at_midnight.zip"
    if nested:
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zipped:
            zipped.writestr("cves.zip", data.getvalue())
        data = outer
        name += ".zip"
    url = f"https://github.com/CVEProject/cvelistV5/releases/download/test/{name}"

    class Client:
        async def get_json(self, target):
            return JSONFetchResult([{"assets": [{"name": name,
                "id": 123, "browser_download_url": url}]}], 200, target)

        async def download(self, target, path):
            path.write_bytes(data.getvalue())

    task = {"page": 1}
    parsed = asyncio.run(baseline_page(Client(), task, tmp_path, CVEProvider()))
    assert len(parsed.entries) == 2
    assert all(item.embedded_detail["_github_link"].startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/") for item in parsed.entries)
    assert task["until"] == "2026-11-13T00:00:00+00:00"
    assert not (tmp_path.parent / "CVE-2025-9999.json").exists()


def test_redownloaded_baseline_is_checked_even_if_an_older_copy_was_verified(tmp_path):
    from types import SimpleNamespace
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zipped:
        zipped.writestr("CVE-2026-1234.json", "{}")

    async def download(url, path):
        path.write_bytes(data.getvalue())

    task = {"page": 1, "asset": {"asset_id": "123", "url": "https://example.test/archive",
        "timestamp": NOW.isoformat(), "digest": "sha256:" + "0" * 64},
        "verified_archive_digest": "sha256:" + "0" * 64}
    with pytest.raises(FetchError, match="checksum"):
        asyncio.run(baseline_page(SimpleNamespace(download=download), task, tmp_path, CVEProvider()))
    assert not list(tmp_path.glob("*.sqlite"))
