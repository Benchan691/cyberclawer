from dataclasses import replace
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, FakeMongoClient
from vuln_scraper.catch_up import run_catch_up_cycle
from vuln_scraper.client import ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.scrapers.fortiguard.config import RSS_URL
from vuln_scraper.scrapers.fortiguard.provider import FortiguardProvider
from vuln_scraper.timestamps import LOCAL_TIMEZONE


FIXTURES = Path(__file__).parent / "fixtures"
FIRST_ID = "fortiguard:FG-IR-26-160"
SECOND_ID = "fortiguard:FG-IR-26-158"


@pytest.fixture
def feed_catch_up(tmp_path, monkeypatch, caplog):
    collection = FakeMongoCollection()
    requests = []
    state = {
        "fail_detail_once": None,
        "feed": (FIXTURES / "list.xml").read_text(encoding="utf-8"),
    }
    detail = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    def respond(request):
        requests.append(str(request.url))
        if str(request.url) == RSS_URL:
            return httpx.Response(200, text=state["feed"])
        if request.url.path.startswith("/psirt/FG-IR-"):
            code = request.url.path.rsplit("/", 1)[-1]
            if state["fail_detail_once"] == code:
                state["fail_detail_once"] = None
                return httpx.Response(503)
            html = detail.replace("FG-IR-26-160", code).replace("fg-ir-26-160", code.lower())
            return httpx.Response(200, text=html)
        if request.url.path.endswith(".json"):
            code = request.url.path.rsplit("_", 1)[-1].removesuffix(".json").upper()
            return httpx.Response(200, json={"document": {"tracking": {"id": code}}})
        raise AssertionError(f"Unexpected request: {request.url}")

    monkeypatch.setattr(
        ScraperClient, "_build_http_client",
        lambda _: httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up", lambda _: [FortiguardProvider()],
    )
    monkeypatch.setattr(
        "vuln_scraper.catch_up.sync_source_catalog_to_mongo",
        lambda *args, **kwargs: {"providers": ["fortiguard"]},
    )
    monkeypatch.setattr(
        "vuln_scraper.runner.collection_from_settings",
        lambda *args, **kwargs: (FakeMongoClient(collection), collection),
    )
    monkeypatch.setattr("vuln_scraper.runner.notify_scrape_failures", lambda *args, **kwargs: False)
    monkeypatch.setattr("vuln_scraper.catch_up.notify_scrape_exception", lambda *args, **kwargs: False)
    caplog.set_level("INFO")
    settings = ScraperSettings(
        data_dir=tmp_path, mongo_enabled=True, mongo_config_file=None,
        mongo_uri="mongodb://unused", mongo_database="test", mongo_collection="news",
        mongo_conflict="skip", scrapers_config_file=None, request_delay=0, retries=0,
    )

    def run(*, limit=1000):
        requests.clear()
        caplog.clear()
        run_catch_up_cycle(replace(settings, limit=limit), days=1)
        return next(
            record.message for record in caplog.records
            if record.message.startswith("Provider fortiguard ")
        )

    return collection, requests, state, run


def test_catch_up_inserts_backdated_feed_and_repairs_missing_or_changed_records(feed_catch_up):
    collection, requests, _, run = feed_catch_up

    summary = run()

    assert set(collection.documents) == {FIRST_ID, SECOND_ID}
    assert "resumable catch-up: checked=2 fetched=2" in summary
    assert "stop_reason=exhausted" in summary
    assert "inserted=2 overwritten=0" in summary
    assert requests.count(RSS_URL) == 1
    for document in collection.documents.values():
        assert document["source"]["provider"] == "fortiguard"
        assert "set fgfm-peercert-withoutsn disable" in document["details"]["content"]

    collection.documents[FIRST_ID]["title"] = "stale title"
    del collection.documents[SECOND_ID]
    summary = run()

    assert set(collection.documents) == {FIRST_ID, SECOND_ID}
    assert collection.documents[FIRST_ID]["title"] != "stale title"
    assert "inserted=1 overwritten=1" in summary

    summary = run()

    assert len(collection.documents) == 2
    assert "inserted=0 overwritten=0" in summary
    assert "skipped=2" in summary


@pytest.mark.parametrize("failure", ["detail", "mongo"])
def test_catch_up_retries_failed_advisories_on_next_scheduled_run(feed_catch_up, failure, caplog):
    collection, _, state, run = feed_catch_up
    if failure == "detail":
        state["fail_detail_once"] = "FG-IR-26-160"
    else:
        collection.fail_insert_once_for = FIRST_ID

    summary = run()

    assert set(collection.documents) == {SECOND_ID}
    assert "stop_reason=error" in summary
    if failure == "mongo":
        assert "mongo_errors=1" in summary
        assert any(
            FIRST_ID in record.message and "MongoDB sync failed" in record.message
            for record in caplog.records
        )

    summary = run()

    assert set(collection.documents) == {FIRST_ID, SECOND_ID}
    assert "inserted=1 overwritten=0" in summary
    assert "skipped=1" in summary
    assert "mongo_errors=0" in summary
    assert "stop_reason=exhausted" in summary


def test_catch_up_empty_feed_preserves_existing_records(feed_catch_up):
    collection, _, state, run = feed_catch_up
    run()
    state["feed"] = "<rss><channel/></rss>"

    summary = run()

    assert set(collection.documents) == {FIRST_ID, SECOND_ID}
    assert "checked=0 fetched=0" in summary
    assert "stop_reason=exhausted" in summary
    assert "deleted=0" in summary


def test_catch_up_full_feed_respects_explicit_record_limit(feed_catch_up):
    collection, requests, _, run = feed_catch_up

    summary = run(limit=1)

    assert set(collection.documents) == {FIRST_ID}
    assert "stop_reason=limit" in summary
    assert requests.count(RSS_URL) == 1
    assert not any(url.endswith("/psirt/FG-IR-26-158") for url in requests)
