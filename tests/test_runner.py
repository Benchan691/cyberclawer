import asyncio
import builtins
import copy
import json
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from vuln_scraper.client import CaptchaRequiredError, FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import Checkpoint, ScraperRunner
from vuln_scraper.scrapers import CiscoProvider
from vuln_scraper.scrapers import CNNVDProvider
from vuln_scraper.scrapers import CNVDProvider
from vuln_scraper.scrapers import CVEProvider
from vuln_scraper.scrapers import GovCERTProvider
from vuln_scraper.scrapers import HKCERTProvider
from vuln_scraper.scrapers import HikvisionProvider
from vuln_scraper.scrapers import HuaweiSAProvider
from vuln_scraper.scrapers import InfoSecProvider
from vuln_scraper.scrapers import JuniperProvider
from vuln_scraper.scrapers import MSRCProvider
from vuln_scraper.scrapers import PaloAltoProvider
from vuln_scraper.scrapers import QianxinProvider
from vuln_scraper.scrapers import RansomwareLiveProvider
from vuln_scraper.scrapers import SplunkProvider
from vuln_scraper.scrapers import ZeroDayProvider

from tests.fake_avd_provider import FakeAvdProvider
from vuln_scraper.timestamps import LOCAL_TIMEZONE, document_updated_time


def test_limit_counts_raw_results(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=2,
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(settings, provider=FakeAvdProvider())._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == [
        "avd:2026-10001",
        "avd:2026-10002",
    ]
    assert output["result_count"] == 2
    assert output["raw_limit"] == 2
    assert client.list_pages_seen == [1]


def test_raw_limit_fetches_detail_only_for_limited_rows(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(settings, provider=FakeAvdProvider())._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert client.list_pages_seen == [1]


def test_mongo_update_empty_collection_fetches_newest_up_to_limit(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=3,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == [
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
    ]
    assert set(collection.documents) == {
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
    }
    assert output["mongo_sync"]["inserted"] == 3
    assert not settings.output_file.exists()
    assert client.list_pages_seen == [1, 2]


def test_mongo_update_stops_when_newest_page_already_known(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "avd:2026-10001": {"_id": "avd:2026-10001", "type": "avd", "code": "2026-10001"},
            "avd:2026-10002": {"_id": "avd:2026-10002", "type": "avd", "code": "2026-10002"},
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert output["mongo_sync"]["inserted"] == 0
    assert output["stop_reason"] == "overlap"
    assert not settings.output_file.exists()
    assert client.list_pages_seen == [1]


def test_stop_on_unchanged_content_fetches_and_stops_when_document_matches(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    seed_output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )
    from vuln_scraper.mongo import build_mongo_document

    collection.documents["avd:2026-10001"] = build_mongo_document(
        seed_output["vulnerabilities"][0],
        seed_output,
    )
    client.list_pages_seen.clear()

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            stop_on_unchanged_content=True,
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert output["stop_reason"] == "overlap"
    assert client.list_pages_seen == [1]


def test_stop_on_unchanged_content_overwrites_when_document_changed(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    seed_output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )
    from vuln_scraper.mongo import build_mongo_document

    stale = build_mongo_document(seed_output["vulnerabilities"][0], seed_output)
    stale["title"] = "stale title"
    collection.documents["avd:2026-10001"] = stale
    client.list_pages_seen.clear()
    changed_settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "changed_checkpoint.json",
        limit=1,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            changed_settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            stop_on_unchanged_content=True,
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert output["mongo_sync"]["overwritten"] == 1
    assert collection.documents["avd:2026-10001"]["title"] != "stale title"


def test_mongo_update_stop_on_first_known_override_sets_overlap(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "avd:2026-10002": {"_id": "avd:2026-10002", "type": "avd", "code": "2026-10002"},
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            stop_on_first_known=True,
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert output["stop_reason"] == "overlap"
    assert client.list_pages_seen == [1]


def test_mongo_update_mixed_page_syncs_new_records_then_stops_on_known_page(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "avd:2026-10002": {"_id": "avd:2026-10002", "type": "avd", "code": "2026-10002"},
            "avd:2026-10003": {"_id": "avd:2026-10003", "type": "avd", "code": "2026-10003"},
            "avd:2026-10004": {"_id": "avd:2026-10004", "type": "avd", "code": "2026-10004"},
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert output["mongo_sync"]["inserted"] == 1
    assert output["stop_reason"] == "limit"
    assert set(collection.documents) == {
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
        "avd:2026-10004",
    }
    assert client.list_pages_seen == [1, 2]


def test_timestamp_catch_up_overwrites_today_records_even_when_known(tmp_path) -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today - timedelta(days=1)
    client = FakeTimestampAVDClient(today.isoformat(), yesterday.isoformat())
    collection = FakeMongoCollection(
        {
            "avd:2026-10001": {
                "_id": "avd:2026-10001",
                "type": "avd",
                "code": "2026-10001",
                "title": "stale title",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=10,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )
    boundary = datetime.combine(today, datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001", "avd:2026-10002"]
    assert output["stop_reason"] == "timestamp_boundary"
    assert output["mongo_sync"]["overwritten"] == 1
    assert output["mongo_sync"]["inserted"] == 1
    assert collection.documents["avd:2026-10001"]["title"] != "stale title"
    assert client.list_pages_seen == [1, 2]
    assert client.detail_ids_seen == ["AVD-2026-10001", "AVD-2026-10002", "AVD-2026-10003"]


def test_timestamp_catch_up_stops_immediately_on_first_older_record(tmp_path) -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today - timedelta(days=1)
    client = FakeTimestampAVDClient([today.isoformat(), yesterday.isoformat()], yesterday.isoformat())
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=10,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )
    boundary = datetime.combine(today, datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert output["stop_reason"] == "timestamp_boundary"
    assert client.list_pages_seen == [1]
    assert client.detail_ids_seen == ["AVD-2026-10001", "AVD-2026-10002"]


def test_timestamp_catch_up_skips_older_records_and_stops(tmp_path) -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today - timedelta(days=1)
    client = FakeTimestampAVDClient(yesterday.isoformat(), yesterday.isoformat())
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=10,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )
    boundary = datetime.combine(today, datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert output["stop_reason"] == "timestamp_boundary"
    assert output["mongo_sync"]["inserted"] == 0
    assert client.list_pages_seen == [1]


def test_timestamp_catch_up_stops_when_page_has_no_parseable_timestamps(tmp_path) -> None:
    client = FakeTimestampAVDClient("not a date", "not a date")
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=10,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )
    boundary = datetime.combine(datetime.now(LOCAL_TIMEZONE).date(), datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=FakeAvdProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert output["stop_reason"] == "timestamp_boundary"
    assert client.list_pages_seen == [1]


def test_timestamp_resolver_uses_fallback_publish_fields() -> None:
    assert document_updated_time(
        {
            "type": "avd",
            "disclosure_date": "2026-06-18",
            "details": {"avd": {}},
        }
    ) == "2026-06-17T16:00:00+00:00"
    assert document_updated_time(
        {
            "type": "govcert",
            "details": {"govcert": {"published_date": "2026-06-18"}},
        }
    ) == "2026-06-17T16:00:00+00:00"
    assert document_updated_time(
        {
            "type": "huawei_sa",
            "details": {"huawei_sa": {"publishDate": "2026-06-18"}},
        }
    ) == "2026-06-17T16:00:00+00:00"
    assert document_updated_time(
        {
            "type": "infosec",
            "details": {"infosec": {"published_date": "2026-06-18"}},
        }
    ) == "2026-06-17T16:00:00+00:00"
    assert document_updated_time(
        {
            "type": "cnnvd",
            "details": {"cnnvd": {"publishDate": "2026-06-18"}},
        }
    ) == "2026-06-17T16:00:00+00:00"
    assert document_updated_time(
        {
            "type": "cnnvd",
            "details": {"cnnvd": {"updateTime": "2026-06-18 12:30:00"}},
        }
    ) == "2026-06-18T04:30:00+00:00"


def test_hkcert_mongo_sync_pages_past_leading_known_records(tmp_path) -> None:
    client = FakeHKCERTClient()
    known_codes = ["p1-a", "p1-b", "p2-a", "p2-b"]
    collection = FakeMongoCollection(
        {f"hkcert:{code}": {"_id": f"hkcert:{code}", "type": "hkcert", "code": code} for code in known_codes}
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "hkcert.json",
        checkpoint_file=tmp_path / "hkcert_checkpoint.json",
        limit=2,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=HKCERTProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["hkcert:p3-a", "hkcert:p3-b"]
    assert output["mongo_sync"]["inserted"] == 2
    assert client.list_pages_seen == [1, 2, 3]


def test_non_mongo_scrape_still_writes_json(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=FakeAvdProvider())._run_with_client(client))

    assert settings.output_file.exists()
    assert "raw_tables" not in output["vulnerabilities"][0]["details"]["avd"]


def test_msrc_monthly_detail_expands_to_cve_records(tmp_path) -> None:
    client = FakeMSRCClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "msrc.json",
        checkpoint_file=tmp_path / "msrc_checkpoint.json",
        limit=2,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=MSRCProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["msrc:2026-41108", "msrc:2026-50001"]
    assert output["result_count"] == 2
    assert output["vulnerabilities"][0]["source"]["detail_url"].endswith("/2026-Jun")
    assert output["vulnerabilities"][0]["details"]["msrc"]["document_id"] == "2026-Jun"
    assert client.headers_seen == [
        {"Accept": "application/json"},
        {"Accept": "application/json"},
        {"Accept": "application/json"},
    ]


def test_cve_mongo_sync_fetches_limit_of_new_records_skipping_known(tmp_path) -> None:
    client = FakeCVEClient(
        delta=[
            cve_delta_batch(
                "2026-06-05T03:00:00.000Z",
                new=["CVE-2026-3000", "CVE-2026-3001"],
            ),
            cve_delta_batch(
                "2026-06-05T02:00:00.000Z",
                new=["CVE-2026-2000"],
            ),
        ]
    )
    collection = FakeMongoCollection(
        {
            "cve:2026-3000": {
                "_id": "cve:2026-3000",
                "type": "cve",
                "code": "2026-3000",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cves.json",
        checkpoint_file=tmp_path / "cve_checkpoint.json",
        limit=2,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CVEProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["cve:2026-3001", "cve:2026-2000"]
    assert output["stop_reason"] == "limit"
    assert output["mongo_sync"]["inserted"] == 2
    assert client.detail_ids_seen == ["CVE-2026-3001", "CVE-2026-2000"]


def test_cve_mongo_sync_stops_when_no_new_records_remain(tmp_path) -> None:
    client = FakeCVEClient(
        delta=[
            cve_delta_batch("2026-06-05T03:00:00.000Z", new=["CVE-2026-3000"]),
        ]
    )
    collection = FakeMongoCollection(
        {
            "cve:2026-3000": {
                "_id": "cve:2026-3000",
                "type": "cve",
                "code": "2026-3000",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        checkpoint_file=tmp_path / "cve_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CVEProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert output["result_count"] == 0
    assert output["mongo_sync"]["inserted"] == 0
    assert client.detail_ids_seen == []


def test_cve_timestamp_catch_up_respects_limit_and_today_window(tmp_path) -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today - timedelta(days=1)
    today_updated = f"{today.isoformat()}T12:00:00.000Z"
    yesterday_updated = f"{yesterday.isoformat()}T12:00:00.000Z"
    client = FakeCVEClient(
        delta=[
            cve_delta_batch(
                "2026-06-05T03:00:00.000Z",
                new=["CVE-2026-3000", "CVE-2026-3001"],
                date_updated=today_updated,
            ),
            cve_delta_batch(
                "2026-06-05T02:00:00.000Z",
                new=["CVE-2026-2000"],
                date_updated=yesterday_updated,
            ),
        ],
        detail_date_updated=today_updated,
    )
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=1,
    )
    boundary = datetime.combine(today, datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CVEProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert output["result_count"] == 1
    assert output["stop_reason"] == "limit"
    assert identities(output["vulnerabilities"])[0] in {"cve:2026-3000", "cve:2026-3001"}
    assert "CVE-2026-2000" not in client.detail_ids_seen


def test_cve_timestamp_catch_up_skips_older_delta_entries(tmp_path) -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today - timedelta(days=1)
    yesterday_updated = f"{yesterday.isoformat()}T12:00:00.000Z"
    client = FakeCVEClient(
        delta=[
            cve_delta_batch(
                "2026-06-05T02:00:00.000Z",
                new=["CVE-2026-2000"],
                date_updated=yesterday_updated,
            ),
        ]
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=10,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
    )
    boundary = datetime.combine(today, datetime.min.time(), tzinfo=LOCAL_TIMEZONE)

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CVEProvider(),
            mongo_client_factory=fake_mongo_factory(FakeMongoCollection()),
            updated_since=boundary,
        )._run_with_client(client)
    )

    assert output["result_count"] == 0
    assert output["stop_reason"] == "no_rows"
    assert client.detail_ids_seen == []


def test_checkpoint_loads_zero_byte_file_and_rejects_malformed_json(tmp_path) -> None:
    checkpoint_file = tmp_path / "checkpoint.json"
    checkpoint_file.touch()

    assert Checkpoint.load(checkpoint_file) == Checkpoint()

    checkpoint_file.write_text("{broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        Checkpoint.load(checkpoint_file)


def test_zeroday_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeZeroDayClient()
    collection = FakeMongoCollection(
        {
            "zeroday:1102": {
                "_id": "zeroday:1102",
                "type": "zeroday",
                "code": "1102",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "zeroday.json",
        checkpoint_file=tmp_path / "zeroday_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=ZeroDayProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["zeroday:1104", "zeroday:1103"]
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"zeroday:1104", "zeroday:1103", "zeroday:1102"}
    assert client.detail_ids_seen == ["1104", "1103"]


def test_huawei_sa_json_provider_converts_api_records_and_skips_empty_cves(tmp_path) -> None:
    client = FakeHuaweiSAClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "huawei_sa.json",
        checkpoint_file=tmp_path / "huawei_sa_checkpoint.json",
        limit=2,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    scraper = ScraperRunner(settings, provider=HuaweiSAProvider())
    output = asyncio.run(scraper._run_with_client(client))

    assert identities(output["vulnerabilities"]) == [
        "huawei_sa:huawei-sa-LKEiSHPVtLPEDF-60937345",
        "huawei_sa:huawei-sa-DViSHDCP-42041136",
    ]
    assert client.post_pages_seen == [1]
    assert client.detail_urls_seen == []

    with_cve, without_cve = output["vulnerabilities"]
    assert with_cve["type"] == "huawei_sa"
    assert with_cve["code"] == "huawei-sa-LKEiSHPVtLPEDF-60937345"
    assert with_cve["cve_code"] == "2026-43284"
    assert with_cve["status"] == "NEW"
    assert with_cve["details"]["huawei_sa"]["cve_ids"] == ["CVE-2026-43284"]
    assert with_cve["source"]["detail_url"].endswith(
        "/enterprise/en/sa/detail/huawei-sa-LKEiSHPVtLPEDF-60937345"
    )

    assert without_cve["cve_code"] is None
    assert without_cve["details"]["huawei_sa"]["cve_ids"] == []


def test_govcert_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeGovCERTClient()
    collection = FakeMongoCollection(
        {
            "govcert:1892": {
                "_id": "govcert:1892",
                "type": "govcert",
                "code": "1892",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "govcert.json",
        checkpoint_file=tmp_path / "govcert_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=GovCERTProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["govcert:1894", "govcert:1893"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-1894"
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"govcert:1894", "govcert:1893", "govcert:1892"}
    assert client.detail_ids_seen == ["1894", "1893"]


def test_paloalto_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakePaloAltoClient()
    collection = FakeMongoCollection(
        {
            "paloalto:CVE-2026-0263": {
                "_id": "paloalto:CVE-2026-0263",
                "type": "paloalto",
                "code": "CVE-2026-0263",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "paloalto.json",
        checkpoint_file=tmp_path / "paloalto_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=PaloAltoProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["paloalto:CVE-2026-0265", "paloalto:PAN-SA-2026-0007"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-0265"
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {
        "paloalto:CVE-2026-0265",
        "paloalto:PAN-SA-2026-0007",
        "paloalto:CVE-2026-0263",
    }
    assert client.detail_ids_seen == ["CVE-2026-0265", "PAN-SA-2026-0007"]


def test_infosec_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeInfoSecClient()
    collection = FakeMongoCollection(
        {
            "infosec:1891": {
                "_id": "infosec:1891",
                "type": "infosec",
                "code": "1891",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "infosec.json",
        checkpoint_file=tmp_path / "infosec_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=InfoSecProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["infosec:1893", "infosec:1892"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-1893"
    assert output["vulnerabilities"][0]["details"]["infosec"]["summary"] == "Summary for 1893."
    assert (
        output["vulnerabilities"][0]["details"]["infosec"]["govcert_detail_url"]
        == "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893"
    )
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"infosec:1893", "infosec:1892", "infosec:1891"}
    assert client.detail_ids_seen == ["1893", "1892"]


def test_splunk_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeSplunkClient()
    collection = FakeMongoCollection(
        {
            "splunk:SVD-2026-0500": {
                "_id": "splunk:SVD-2026-0500",
                "type": "splunk",
                "code": "SVD-2026-0500",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "splunk.json",
        checkpoint_file=tmp_path / "splunk_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=SplunkProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["splunk:SVD-2026-0516", "splunk:SVD-2026-0501"]
    assert output["vulnerabilities"][0]["cve_code"] == "2025-68161"
    assert output["vulnerabilities"][0]["details"]["splunk"]["product_status"][0]["fix_version"] == "4.0.1"
    assert output["vulnerabilities"][0]["details"]["splunk"]["raw_tables"][0][0] == [
        "Package",
        "Remediation",
        "CVE",
        "Severity",
    ]
    assert "raw_tables" not in collection.documents["splunk:SVD-2026-0516"]["details"]["splunk"]
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"splunk:SVD-2026-0516", "splunk:SVD-2026-0501", "splunk:SVD-2026-0500"}
    assert client.detail_ids_seen == ["SVD-2026-0516", "SVD-2026-0501"]


def test_hikvision_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeHikvisionClient()
    collection = FakeMongoCollection(
        {
            "hikvision:hsrc-2026-0002": {
                "_id": "hikvision:hsrc-2026-0002",
                "type": "hikvision",
                "code": "hsrc-2026-0002",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "hikvision.json",
        checkpoint_file=tmp_path / "hikvision_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=HikvisionProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["hikvision:hsrc-2026-0003"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-0003"
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {"hikvision:hsrc-2026-0003", "hikvision:hsrc-2026-0002"}
    assert client.detail_ids_seen == ["hsrc-2026-0003"]
    assert client.force_browser_seen == [True, True]


def test_cnnvd_mongo_sync_skips_leading_known_records(tmp_path) -> None:
    client = FakeCNNVDClient()
    known_id = "202606-1911"
    collection = FakeMongoCollection(
        {
            f"cnnvd:{known_id}": {
                "_id": f"cnnvd:{known_id}",
                "type": "cnnvd",
                "code": known_id,
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CNNVDProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["cnnvd:202606-1910"]
    assert output["mongo_sync"]["inserted"] == 1
    assert client.detail_ids_seen == ["record-1910"]


def test_cnnvd_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeCNNVDClient()
    known_id = "202606-1910"
    collection = FakeMongoCollection(
        {
            f"cnnvd:{known_id}": {
                "_id": f"cnnvd:{known_id}",
                "type": "cnnvd",
                "code": known_id,
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CNNVDProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["cnnvd:202606-1911"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-11628"
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {
        "cnnvd:202606-1911",
        f"cnnvd:{known_id}",
    }
    assert client.detail_ids_seen == ["record-1911"]


def test_cnnvd_detail_requests_stop_after_first_success(tmp_path) -> None:
    client = FakeCNNVDClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["cnnvd:202606-1911"]
    assert output["vulnerabilities"][0]["details"]["cnnvd"] == cnnvd_detail_payload("record-1911")["data"]
    assert output["vulnerabilities"][0]["source"]["detail_url"].endswith("/frontend/detail?vulId=record-1911")
    assert client.detail_payloads == [{"id": "record-1911"}]


def test_successful_run_output_ignores_stale_checkpoint_failures(tmp_path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "failed": [
                    {
                        "identity": "LIST",
                        "type": "LIST",
                        "code": "",
                        "phase": "list",
                        "url": "https://www.cnnvd.org.cn/web/homePage/vulWarnList",
                        "error": "Failed to fetch https://www.cnnvd.org.cn/web/homePage/vulWarnList",
                        "updated_at": "2026-06-08T10:50:53.582138+00:00",
                    },
                    {
                        "identity": "cnnvd:0f9ea9d7144547dcaf6374acae1c7b97",
                        "type": "CNNVD",
                        "code": "0f9ea9d7144547dcaf6374acae1c7b97",
                        "phase": "detail",
                        "url": "https://www.cnnvd.org.cn/home/warn?warnId=0f9ea9d7144547dcaf6374acae1c7b97",
                        "error": "CNNVD detail response did not contain a warning object",
                        "updated_at": "2026-06-08T16:20:12.342869+00:00",
                    },
                    {
                        "identity": "zeroday:157",
                        "type": "ZERODAY",
                        "code": "157",
                        "phase": "detail",
                        "url": "https://www.zero-day.cz/database/157/",
                        "error": "dns failure",
                        "updated_at": "2026-06-08T10:49:00.346439+00:00",
                    },
                ],
                "completed_identity_keys": [],
            }
        ),
        encoding="utf-8",
    )
    client = FakeCNNVDClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=checkpoint,
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    assert output["result_count"] == 1
    assert output["failed"] == []
    saved = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert not any(str(item.get("identity", "")).startswith("cnnvd:") for item in saved["failed"])
    assert not any("vulWarnList" in str(item.get("url", "")) for item in saved["failed"])
    assert any(item.get("identity") == "zeroday:157" for item in saved["failed"])


def test_cnnvd_fetches_one_list_page_for_multiple_details(tmp_path) -> None:
    client = FakeCNNVDClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=3,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    assert output["result_count"] == 3
    assert client.list_request_count == 1
    assert client.detail_ids_seen == ["record-1911", "record-1910", "record-1909"]


def test_cnnvd_detail_requests_use_internal_id(tmp_path) -> None:
    client = FakeCNNVDClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["cnnvd:202606-1911"]
    assert client.detail_payloads == [{"id": "record-1911"}]


def test_cnnvd_detail_api_error_is_not_fallback(tmp_path) -> None:
    client = FakeCNNVDClient(detail_api_error=True)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    detail = output["vulnerabilities"][0]["details"]["cnnvd"]
    assert detail["_list_summary"] is True
    assert len(output["failed"]) == 1
    assert "CNNVD detail API error 5001" in output["failed"][0]["error"]
    assert "request_json={'id': 'record-1911'}" in output["failed"][0]["error"]


def test_cnnvd_detail_captcha_refreshes_session_and_retries(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(
        "vuln_scraper.runner.random_user_agent",
        lambda *, exclude=None: "rotated-ua",
    )
    client = FakeCNNVDClient(captcha_required=1)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(
        ScraperRunner(settings, provider=CNNVDProvider(user_agent="initial-ua"))._run_with_client(client)
    )

    assert output["failed"] == []
    assert output["vulnerabilities"][0]["details"]["cnnvd"]["id"] == "record-1911"
    assert client.detail_payloads == [{"id": "record-1911"}, {"id": "record-1911"}]
    assert client.refresh_count == 1
    assert client.user_agents == ["initial-ua", "rotated-ua"]


def test_cnnvd_list_captcha_refreshes_session_and_retries(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(
        "vuln_scraper.runner.random_user_agent",
        lambda *, exclude=None: "rotated-ua",
    )
    client = FakeCNNVDClient(list_captcha_required=1)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(
        ScraperRunner(settings, provider=CNNVDProvider(user_agent="initial-ua"))._run_with_client(client)
    )

    assert output["failed"] == []
    assert client.list_request_count == 2
    assert client.refresh_count == 1
    assert client.list_user_agents == ["initial-ua", "rotated-ua"]


def test_cnnvd_captcha_required_refreshes_session_until_success(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    rotations = iter(["rotated-ua-1", "rotated-ua-2"])

    async def fast_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(
        "vuln_scraper.runner.random_user_agent",
        lambda *, exclude=None: next(rotations),
    )
    client = FakeCNNVDClient(captcha_required=2)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CNNVDProvider(user_agent="initial-ua", captcha_retries=2),
        )._run_with_client(client)
    )

    assert output["failed"] == []
    assert output["vulnerabilities"][0]["details"]["cnnvd"]["id"] == "record-1911"
    assert client.detail_payloads == [{"id": "record-1911"}, {"id": "record-1911"}, {"id": "record-1911"}]
    assert client.refresh_count == 2
    assert client.user_agents == ["initial-ua", "rotated-ua-1", "rotated-ua-2"]


def test_cnnvd_retries_transient_unparseable_detail_response(tmp_path) -> None:
    client = FakeCNNVDClient(empty_detail_once=True)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnnvd.json",
        checkpoint_file=tmp_path / "cnnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CNNVDProvider())._run_with_client(client))

    assert output["failed"] == []
    assert output["vulnerabilities"][0]["details"]["cnnvd"]["id"] == "record-1911"
    assert client.detail_payloads == [{"id": "record-1911"}, {"id": "record-1911"}]


def test_json_request_finalizer_runs_before_fetch(tmp_path) -> None:
    class Provider(CNNVDProvider):
        async def finalize_json_request(self, client, request):
            request = dict(request)
            request["headers"] = {"X-Test": "finalized"}
            return request

    class Client:
        def __init__(self) -> None:
            self.headers = None

        async def request_json(self, method: str, url: str, *, headers=None, json_body=None, data=None):
            self.headers = headers
            return FakeJSONResult({"ok": True}, url)

    runner = ScraperRunner(
        ScraperSettings(data_dir=tmp_path, output_file=tmp_path / "out.json", checkpoint_file=tmp_path / "cp.json"),
        provider=Provider(),
    )
    client = Client()

    asyncio.run(runner._fetch_json_request(client, {"method": "POST", "url": "https://example.test", "json": {}}))

    assert client.headers == {"X-Test": "finalized"}


def test_cnvd_mongo_sync_stops_at_first_known_record_and_forces_browser(tmp_path) -> None:
    client = FakeCNVDClient()
    collection = FakeMongoCollection(
        {
            "cnvd:2026-21549": {
                "_id": "cnvd:2026-21549",
                "type": "cnvd",
                "code": "2026-21549",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnvd.json",
        checkpoint_file=tmp_path / "cnvd_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CNVDProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["cnvd:2026-21550"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-12345"
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {"cnvd:2026-21550", "cnvd:2026-21549"}
    assert client.detail_ids_seen == ["2026-21550"]
    assert client.force_browser_seen == [False, False]


def test_juniper_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeJuniperClient()
    collection = FakeMongoCollection(
        {
            "juniper:JSA93455": {
                "_id": "juniper:JSA93455",
                "type": "juniper",
                "code": "JSA93455",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "juniper.json",
        checkpoint_file=tmp_path / "juniper_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=JuniperProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["juniper:JSA93456"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-55555"
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {"juniper:JSA93456", "juniper:JSA93455"}
    assert client.detail_slugs_seen == ["JSA93456"]


def test_juniper_fetches_second_list_page_when_limit_exceeds_page_size(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "vuln_scraper.scrapers.juniper.provider.get_coveo_config",
        lambda page_uri="/s/global-search/@uri": {
            "organizationId": "junipernetworks",
            "accessToken": "test-token",
        },
    )
    known = {f"juniper:JSA{93456 - index}" for index in range(10)}
    client = FakeJuniperClient()
    collection = FakeMongoCollection({identity: {"_id": identity} for identity in known})
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "juniper.json",
        checkpoint_file=tmp_path / "juniper_checkpoint.json",
        limit=15,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=4,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=JuniperProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert len(identities(output["vulnerabilities"])) == 15
    expected_new_codes = {f"JSA{93456 - index}" for index in range(10, 25)}
    assert {record["code"] for record in output["vulnerabilities"]} == expected_new_codes
    list_offsets = [request["json"]["firstResult"] for request in client.list_requests]
    assert 0 in list_offsets
    assert 10 in list_offsets


def test_cisco_json_provider_uses_bearer_header_and_embeds_detail(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CISCO_OPENVULN_TOKEN", "token-123")
    client = FakeCiscoClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cisco.json",
        checkpoint_file=tmp_path / "cisco_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=CiscoProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["cisco:cisco-sa-foo-123"]
    record = output["vulnerabilities"][0]
    assert record["cve_code"] == "2026-12345"
    assert record["details"]["cisco"]["advisory_id"] == "cisco-sa-foo-123"
    assert client.headers_seen == [
        {"Accept": "application/json", "Authorization": "Bearer token-123"},
    ]


def test_qianxin_json_provider_preserves_nested_html_tables(tmp_path) -> None:
    client = FakeQianxinClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "qianxin.json",
        checkpoint_file=tmp_path / "qianxin_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=QianxinProvider())._run_with_client(client))

    detail = output["vulnerabilities"][0]["details"]["qianxin"]
    assert detail["raw_tables"] == [
        [["Product", "Versions"], ["Redis", "Redis < 8.0"]]
    ]
    assert detail["title"] == "Redis security advisory"
    assert "vulnerability_information" in detail["description"]


def test_cisco_json_provider_missing_auth_fails_before_fetch(tmp_path, monkeypatch) -> None:
    for name in (
        "CISCO_OPENVULN_TOKEN",
        "CISCO_OPENVULN_CLIENT_ID",
        "CISCO_OPENVULN_CLIENT_SECRET",
        "CISCO_CLIENT_ID",
        "CISCO_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    client = FakeNoCallJSONClient()
    events: list[dict] = []
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cisco.json",
        checkpoint_file=tmp_path / "cisco_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(
        ScraperRunner(
            settings,
            provider=CiscoProvider(),
            progress_callback=events.append,
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert not client.called
    assert any(
        event["phase"] == "list-failed" and "requires authentication" in event["error"]
        for event in events
    )
    
class FakeHuaweiSAClient:
    def __init__(self) -> None:
        self.post_pages_seen: list[int] = []
        self.detail_urls_seen: list[str] = []

    async def post_json(self, url: str, *, json=None, headers=None):
        parsed = urlparse(url)
        self.post_pages_seen.append(int(parse_qs(parsed.query)["pageIndex"][0]))
        return FakeJSONResult(
            {
                "status": "200",
                "page": {"totalPages": 1, "total": 2},
                "data": [
                    {
                        "allPath": None,
                        "vul": [
                            {
                                "hwPsirtId": "HWPSIRT-2026-27380",
                                "cveId": "CVE-2026-43284",
                            }
                        ],
                        "isAllPermission": None,
                        "lang": "en",
                        "permission": False,
                        "publishDate": "2026-06-01",
                        "sasnId": None,
                        "sasnNo": "huawei-sa-LKEiSHPVtLPEDF-60937345",
                        "sasnVersion": "1.9",
                        "severity": "High",
                        "summary": "Kernel issue",
                        "title": "Linux Kernel ESP Vulnerability",
                        "type": None,
                    },
                    {
                        "allPath": None,
                        "vul": [
                            {
                                "hwPsirtId": "HWPSIRT-2026-29427",
                                "cveId": "",
                            }
                        ],
                        "isAllPermission": None,
                        "lang": "en",
                        "permission": False,
                        "publishDate": "2026-05-28",
                        "sasnId": None,
                        "sasnNo": "huawei-sa-DViSHDCP-42041136",
                        "sasnVersion": "1.3",
                        "severity": "High",
                        "summary": "DoS issue",
                        "title": "DoS Vulnerability in Some Huawei Data Communication Products",
                        "type": None,
                    },
                ],
            },
            url,
        )

    async def get_json(self, url: str, *, headers=None):
        self.detail_urls_seen.append(url)
        return FakeJSONResult({}, url)


def test_ransomwarelive_json_provider_uses_api_key_and_embeds_detail(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "rw-key")
    client = FakeRansomwareLiveClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "ransomwarelive.json",
        checkpoint_file=tmp_path / "ransomwarelive_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=RansomwareLiveProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["ransomwarelive:QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw"]
    record = output["vulnerabilities"][0]
    assert record["cve_code"] is None
    assert record["title"] == "Acme Hospital"
    assert record["details"]["ransomwarelive"]["group"] == "lockbit3"
    assert client.headers_seen == [
        {"Accept": "application/json", "X-API-KEY": "rw-key"},
    ]


def test_ransomwarelive_missing_auth_is_reported_in_output(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.delenv("RANSOM_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    client = FakeNoCallJSONClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "ransomwarelive.json",
        checkpoint_file=tmp_path / "ransomwarelive_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=RansomwareLiveProvider())._run_with_client(client))

    assert output["vulnerabilities"] == []
    assert not client.called
    assert output["failed"]
    assert "RANSOMWARE_LIVE_API_KEY" in output["failed"][0]["error"]
    assert "RANSOM_API_KEY" in output["failed"][0]["error"]


class FakeHKCERTClient:
    def __init__(self) -> None:
        self.list_pages_seen: list[int] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path.endswith("/security-bulletin") and "page" in parse_qs(parsed.query):
            page = int(parse_qs(parsed.query)["page"][0])
            self.list_pages_seen.append(page)
            return FetchResult(html=hkcert_list_html(page), status_code=200, url=url)

        slug = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        return FetchResult(html=hkcert_detail_html(slug), status_code=200, url=url)


class FakeClient:
    def __init__(self) -> None:
        self.list_pages_seen: list[int] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path.endswith("/high-risk/list"):
            page = int(parse_qs(parsed.query)["page"][0])
            self.list_pages_seen.append(page)
            return FetchResult(html=list_page_html(page), status_code=200, url=url)

        avd_id = parse_qs(parsed.query)["id"][0]
        return FetchResult(html=detail_html(avd_id), status_code=200, url=url)


class FakeTimestampAVDClient:
    def __init__(self, page_one_date: str | list[str], page_two_date: str | list[str]) -> None:
        self.page_one_date = page_one_date
        self.page_two_date = page_two_date
        self.list_pages_seen: list[int] = []
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path.endswith("/high-risk/list"):
            page = int(parse_qs(parsed.query)["page"][0])
            self.list_pages_seen.append(page)
            date = self.page_one_date if page == 1 else self.page_two_date
            return FetchResult(html=timestamp_list_page_html(page, date), status_code=200, url=url)

        avd_id = parse_qs(parsed.query)["id"][0]
        self.detail_ids_seen.append(avd_id)
        return FetchResult(html=detail_html(avd_id), status_code=200, url=url)


class FakeCVEClient:
    def __init__(self, *, delta: list[dict] | None = None, detail_date_updated: str | None = None) -> None:
        self.delta = delta or []
        self.detail_date_updated = detail_date_updated
        self.urls_seen: list[str] = []
        self.detail_ids_seen: list[str] = []

    async def get_json(self, url: str, *, headers=None):
        self.urls_seen.append(url)
        if url.endswith("/deltaLog.json"):
            return FakeJSONResult(self.delta, url)
        cve_id = url.rsplit("/", 1)[-1].removesuffix(".json")
        self.detail_ids_seen.append(cve_id)
        return FakeJSONResult(
            cve_v5_record(cve_id, date_updated=self.detail_date_updated or "2026-06-05T00:00:00.000Z"),
            url,
        )


class FakeMSRCClient:
    def __init__(self) -> None:
        self.headers_seen: list[dict] = []

    async def get_json(self, url: str, *, headers=None):
        self.headers_seen.append(dict(headers or {}))
        fixture = "list.json" if "/Updates" in url else "detail.json"
        payload = json.loads(
            (Path(__file__).parent / "scrapers" / "msrc" / "fixtures" / fixture).read_text(
                encoding="utf-8"
            )
        )
        return FakeJSONResult(payload, url)


class FakeFailingCVEClient(FakeCVEClient):
    def __init__(self, *, delta: list[dict], fail_detail_for: str) -> None:
        super().__init__(delta=delta)
        self.fail_detail_for = fail_detail_for

    async def get_json(self, url: str, *, headers=None):
        if url.endswith(f"/{self.fail_detail_for}.json"):
            self.detail_ids_seen.append(self.fail_detail_for)
            raise RuntimeError("simulated detail failure")
        return await super().get_json(url, headers=headers)


class FakeZeroDayClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path == "/database/":
            return FetchResult(html=zeroday_list_html(), status_code=200, url=url)

        code = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        self.detail_ids_seen.append(code)
        return FetchResult(html=zeroday_detail_html(code), status_code=200, url=url)


class FakeGovCERTClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path == "/en/alerts.php":
            return FetchResult(html=govcert_list_html(), status_code=200, url=url)

        code = parse_qs(parsed.query)["id"][0]
        self.detail_ids_seen.append(code)
        return FetchResult(html=govcert_detail_html(code), status_code=200, url=url)


class FakePaloAltoClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path == "/":
            return FetchResult(html=paloalto_list_html(), status_code=200, url=url)

        code = parsed.path.strip("/")
        self.detail_ids_seen.append(code)
        return FetchResult(html=paloalto_detail_html(code), status_code=200, url=url)


class FakeInfoSecClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.netloc == "www.infosec.gov.hk":
            return FetchResult(html=infosec_list_html(), status_code=200, url=url)

        code = parse_qs(parsed.query)["id"][0]
        self.detail_ids_seen.append(code)
        return FetchResult(html=govcert_detail_html(code), status_code=200, url=url)


class FakeSplunkClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.netloc == "advisory.splunk.com" and parsed.path in {"", "/"}:
            return FetchResult(html=splunk_list_html(), status_code=200, url=url)

        code = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        self.detail_ids_seen.append(code)
        return FetchResult(html=splunk_detail_html(code), status_code=200, url=url)


class FakeHikvisionClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []
        self.force_browser_seen: list[bool] = []

    async def get_html(self, url: str, *, force_browser: bool = False) -> FetchResult:
        self.force_browser_seen.append(force_browser)
        parsed = urlparse(url)
        if parsed.path.rstrip("/").endswith("/security-advisory"):
            return FetchResult(html=hikvision_list_html(), status_code=200, url=url)

        code = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        self.detail_ids_seen.append(code)
        return FetchResult(html=hikvision_detail_html(code), status_code=200, url=url)


class FakeCNNVDClient:
    def __init__(
        self,
        *,
        detail_api_error: bool = False,
        empty_detail_once: bool = False,
        captcha_required: bool | int = False,
        list_captcha_required: bool | int = False,
    ) -> None:
        self.detail_api_error = detail_api_error
        self.empty_detail_once = empty_detail_once
        self.captcha_required = captcha_required
        self.list_captcha_required = list_captcha_required
        self.list_request_count = 0
        self.detail_ids_seen: list[str] = []
        self.detail_payloads: list[dict] = []
        self.user_agents: list[str | None] = []
        self.list_user_agents: list[str | None] = []
        self.refresh_count = 0
        self.refreshed_headers: list[dict[str, str] | None] = []

    async def refresh_session(self, headers=None) -> None:
        self.refresh_count += 1
        self.refreshed_headers.append(dict(headers) if headers else None)

    async def request_json(self, method: str, url: str, *, headers=None, json_body=None, data=None):
        user_agent = (headers or {}).get("User-Agent")
        if url.endswith("/searchVul"):
            self.list_user_agents.append(user_agent)
        elif url.endswith("/searchVulById"):
            self.user_agents.append(user_agent)
        if url.endswith("/tourist/sign"):
            return FakeJSONResult({"code": 200, "data": "test-signature"}, url)
        if url.endswith("/searchVul"):
            self.list_request_count += 1
            if self._should_return_list_captcha():
                return FakeJSONResult({"code": 4010, "success": False, "message": "需要人机验证", "data": None}, url)
            return FakeJSONResult(cnnvd_list_payload(), url)

        payload = dict(json_body or data or {})
        self.detail_payloads.append(payload)
        if self.empty_detail_once:
            self.empty_detail_once = False
            return FakeJSONResult({"code": 200, "success": True, "data": None}, url)
        if self.detail_api_error:
            return FakeJSONResult(
                {"code": 5001, "success": False, "message": "参数错误[文档 ID 不能为空]", "data": None},
                url,
            )
        if self._should_return_detail_captcha():
            return FakeJSONResult({"code": 4010, "success": False, "message": "需要人机验证", "data": None}, url)
        record_id = payload.get("id") or "record-1911"
        self.detail_ids_seen.append(record_id)
        return FakeJSONResult(cnnvd_detail_payload(record_id), url)

    def _should_return_detail_captcha(self) -> bool:
        if self.captcha_required is True:
            return True
        if self.captcha_required:
            self.captcha_required = int(self.captcha_required) - 1
            return True
        return False

    def _should_return_list_captcha(self) -> bool:
        if self.list_captcha_required is True:
            return True
        if self.list_captcha_required:
            self.list_captcha_required = int(self.list_captcha_required) - 1
            return True
        return False


class FakeCNVDClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []
        self.force_browser_seen: list[bool] = []

    async def get_html(self, url: str, *, force_browser: bool = False) -> FetchResult:
        self.force_browser_seen.append(force_browser)
        parsed = urlparse(url)
        if parsed.path == "/flaw/list":
            return FetchResult(html=cnvd_list_html(), status_code=200, url=url)

        display = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        code = display.removeprefix("CNVD-")
        self.detail_ids_seen.append(code)
        return FetchResult(html=cnvd_detail_html(code), status_code=200, url=url)


class FakeJuniperClient:
    def __init__(self) -> None:
        self.detail_slugs_seen: list[str] = []
        self.list_requests: list[dict] = []

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers=None,
        json_body=None,
        data=None,
    ):
        self.list_requests.append({"method": method, "url": url, "json": json_body})
        if json_body and json_body.get("fieldsToInclude"):
            slug = str(json_body.get("q", "")).split('"')[1] if '"' in str(json_body.get("q", "")) else ""
            if not slug:
                slug = "JSA93456"
            self.detail_slugs_seen.append(slug)
            return FakeJSONResult(juniper_detail_coveo_payload(slug), url)
        first_result = int((json_body or {}).get("firstResult", 0))
        return FakeJSONResult(juniper_list_coveo_payload(first_result=first_result), url)


class FakeCiscoClient:
    def __init__(self) -> None:
        self.headers_seen: list[dict | None] = []

    async def get_json(self, url: str, *, headers=None):
        self.headers_seen.append(dict(headers or {}))
        parsed = urlparse(url)
        if parsed.path.endswith("/all"):
            return FakeJSONResult(
                {
                    "advisories": [
                        {
                            "advisoryId": "cisco-sa-foo-123",
                            "advisoryTitle": "Cisco Product Remote Code Execution Vulnerability",
                            "cves": "CVE-2026-12345",
                            "firstPublished": "2026-05-20T15:00:00",
                            "status": "Final",
                            "sir": "Critical",
                        }
                    ],
                    "paging": {"count": 1, "next": "NA", "prev": "NA"},
                },
                url,
            )
        return FakeJSONResult(
            {
                "advisories": [
                    {
                        "advisoryId": "cisco-sa-foo-123",
                        "advisoryTitle": "Cisco Product Remote Code Execution Vulnerability",
                        "cves": "CVE-2026-12345",
                        "firstPublished": "2026-05-20T15:00:00",
                        "status": "Final",
                        "sir": "Critical",
                    }
                ]
            },
            url,
        )


class FakeQianxinClient:
    async def request_json(self, method: str, url: str, *, headers=None, json_body=None, data=None):
        return FakeJSONResult(
            {
                "data": {
                    "data": [
                        {
                            "id": 1868,
                            "title": "Redis security advisory",
                            "category": "风险通告",
                            "level": "高危",
                            "update_time": "2026-06-03",
                        }
                    ],
                    "total": 1,
                }
            },
            url,
        )

    async def get_json(self, url: str, *, headers=None):
        return FakeJSONResult(
            {
                "data": {
                    "id": 1868,
                    "title": "Redis security advisory",
                    "content": """
                    <h1>第二章 漏洞信息</h1>
                    <table>
                      <tr><th>Product</th><th>Versions</th></tr>
                      <tr><td>Redis</td><td>Redis &lt; 8.0</td></tr>
                    </table>
                    """,
                }
            },
            url,
        )


class FakeRansomwareLiveClient:
    def __init__(self) -> None:
        self.headers_seen: list[dict | None] = []

    async def get_json(self, url: str, *, headers=None):
        self.headers_seen.append(dict(headers or {}))
        return FakeJSONResult(
            [
                {
                    "id": "QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw",
                    "victim": "Acme Hospital",
                    "group": "lockbit3",
                    "attackdate": "2026-05-30",
                    "discovered": "2026-06-02T10:15:00Z",
                    "country": "US",
                    "activity": "Healthcare",
                    "website": "acme.example",
                    "screenshot": "https://images.ransomware.live/screenshots/acme.png",
                    "infostealer": {"employees": 4},
                    "press": "https://news.example/acme-ransomware",
                    "permalink": "https://www.ransomware.live/id/QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw",
                }
            ],
            url,
        )


class FakeNoCallJSONClient:
    def __init__(self) -> None:
        self.called = False

    async def get_json(self, url: str, *, headers=None):
        self.called = True
        raise AssertionError("missing provider auth should prevent JSON fetch")


class FakeJSONResult:
    def __init__(self, data: dict, url: str) -> None:
        self.data = data
        self.status_code = 200
        self.url = url


def list_page_html(page: int) -> str:
    rows = {
        1: [
            ("AVD-2026-10001", "Product RCE (CVE-2026-10001)", "CWE-78"),
            ("AVD-2026-10002", "Supply chain poisoning event", "未定义"),
        ],
        2: [
            ("AVD-2026-10003", "Kernel bug", "CWE-120"),
            ("AVD-2026-10004", "Another event", "未定义"),
        ],
    }[page]
    body = "\n".join(
        f"""
        <tr>
          <td><a href="/detail?id={avd_id}">{avd_id}</a></td>
          <td>{title}</td>
          <td>{vuln_type}</td>
          <td>2026-01-0{index}</td>
          <td>CVE PoC</td>
        </tr>
        """
        for index, (avd_id, title, vuln_type) in enumerate(rows, start=1)
    )
    return f"""
    <table>
      <tr><th>AVD编号</th><th>漏洞名称</th><th>漏洞类型</th><th>披露时间</th><th>漏洞状态</th></tr>
      {body}
    </table>
    <div>第 {page} 页 / 2 页 • 总计 4 条记录</div>
    """


def timestamp_list_page_html(page: int, disclosure_date: str | list[str]) -> str:
    rows = {
        1: [
            ("AVD-2026-10001", "Product RCE (CVE-2026-10001)", "CWE-78"),
            ("AVD-2026-10002", "Supply chain poisoning event", "未定义"),
        ],
        2: [
            ("AVD-2026-10003", "Kernel bug", "CWE-120"),
            ("AVD-2026-10004", "Another event", "未定义"),
        ],
    }[page]
    dates = disclosure_date if isinstance(disclosure_date, list) else [disclosure_date] * len(rows)
    body = "\n".join(
        f"""
        <tr>
          <td><a href="/detail?id={avd_id}">{avd_id}</a></td>
          <td>{title}</td>
          <td>{vuln_type}</td>
          <td>{date}</td>
          <td>CVE PoC</td>
        </tr>
        """
        for (avd_id, title, vuln_type), date in zip(rows, dates, strict=False)
    )
    return f"""
    <table>
      <tr><th>AVD编号</th><th>漏洞名称</th><th>漏洞类型</th><th>披露时间</th><th>漏洞状态</th></tr>
      {body}
    </table>
    <div>第 {page} 页 / 2 页 • 总计 4 条记录</div>
    """


def detail_html(avd_id: str) -> str:
    cve_by_id = {
        "AVD-2026-10001": "CVE-2026-10001",
        "AVD-2026-10003": "CVE-2026-10003",
    }
    title = f"Detail {cve_by_id[avd_id]}" if avd_id in cve_by_id else "Detail without CVE"
    return f"""
    <span class="header__title__text">{title}</span>
    <span class="badge btn-primary">高危</span>
    <div class="text-detail">description {avd_id}</div>
    """


def zeroday_list_html() -> str:
    rows = [
        ("1104", "Newest remote code execution", "CVE-2026-1104", "Remote code execution", "2026-06-04"),
        ("1103", "Next privilege escalation", "CVE-2026-1103", "Privilege escalation", "2026-06-03"),
        ("1102", "Known authentication bypass", "CVE-2026-1102", "Authentication bypass", "2026-06-02"),
        ("1101", "Older unknown issue", "CVE-2026-1101", "Path traversal", "2026-06-01"),
    ]
    body = "\n".join(
        f"""
        <div class="issue" id="item_{index}">
          <h3 class="issue-title">
            <a href="/database/{code}/">{title}<br><span class="issue-code">{cve_id}</span></a>
          </h3>
          <div class="description">
            <p class="desc-title">{vuln_type}</p>
            <p>Summary for {code}</p>
          </div>
          <div class="issue-status">
            <div class="discavered"><time>{date}</time></div>
            <div class="patched"><time>{date}</time></div>
          </div>
          <div class="spec"><strong>Product {code}</strong></div>
        </div>
        """
        for index, (code, title, cve_id, vuln_type, date) in enumerate(rows)
    )
    return f"""
    <div id="last_vulnerabilities">
      <p>Zero-day vulnerabilities discovered: 4</p>
      <div id="issuew_wrap">{body}</div>
    </div>
    """


def zeroday_detail_html(code: str) -> str:
    return f"""
    <div id="last_vulnerabilities">
      <div class="issue">
        <h3 class="issue-title">Weakness {code}<br><span class="issue-code">CVE-2026-{code}</span></h3>
        <div class="issue-status">
          <div class="discavered"><time>2026-06-01</time></div>
          <div class="patched"><time>2026-06-01</time></div>
        </div>
        <div class="description">
          <p><b>Advisory</b>: <a href="https://example.test/advisory/{code}">Advisory {code}</a></p>
          <p><b>Vulnerable component:</b> Product {code}</p>
          <p><b>CVE-ID</b>: CVE-2026-{code}</p>
          <p><b>CVSSv3 score</b>: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</p>
          <p><b>CWE-ID</b>: CWE-78 - OS Command Injection</p>
          <p><b>Description</b>:</p>
          <p>Detail for {code}</p>
        </div>
      </div>
    </div>
    """


def govcert_list_html() -> str:
    rows = [
        ("1894", "High Threat Security Alert (A26-06-01): Vulnerability in Linux Kernel", "01-June-2026"),
        ("1893", "Security Alert (A26-05-48): Multiple Vulnerabilities in Microsoft Edge", "29-May-2026"),
        ("1892", "Security Alert (A26-05-47): Multiple Vulnerabilities in Google Chrome", "29-May-2026"),
        ("1891", "High Threat Security Alert (A26-05-46): Multiple Vulnerabilities in Oracle Products", "29-May-2026"),
    ]
    body = "\n".join(
        f"""
        <div class="view-row">
          <div class="view-col-1">
            <span class="label label-primary">{date}</span>
            <a href="alerts_detail.php?id={code}">{title}</a>
          </div>
        </div>
        """
        for code, title, date in rows
    )
    return f"""
    <span class="total_page">1</span>
    <div class="view-table">{body}</div>
    """


def infosec_list_html() -> str:
    rows = [
        ("1893", "Security Alert (A26-05-48): Multiple Vulnerabilities in Microsoft Edge", "2026-5-29"),
        ("1892", "Security Alert (A26-05-47): Multiple Vulnerabilities in Google Chrome", "2026-5-29"),
        ("1891", "High Threat Security Alert (A26-05-46): Multiple Vulnerabilities in Oracle Products", "2026-5-29"),
        ("1890", "High Threat Security Alert (A26-05-45): Multiple Vulnerabilities in Linux Kernel", "2026-5-26"),
    ]
    body = "\n".join(
        f"""
        <div class="newsrow flexbox alert">
          <div class="newsdate"><div>{date}</div><div></div></div>
          <a target="_blank" href="https://www.govcert.gov.hk/en/alerts_detail.php?id={code}">
            <div class="newsdata"><div class="newstitle">{title}</div></div>
          </a>
          <div class="newscontent">Summary for {code}.</div>
        </div>
        """
        for code, title, date in rows
    )
    return f"""<div class="listing">{body}</div>"""


def govcert_detail_html(code: str) -> str:
    return f"""
    <h1 id="doc_title">Security Alert (A26-06-01): Test Alert {code}</h1>
    <p class="text-content">Published on: 01 June 2026</p>
    <div class="noneditable">
      <h4>Description:</h4>
      <p>Detail for CVE-2026-{code}</p>
      <h4>Affected Systems:</h4>
      <ul><li>Product {code}</li></ul>
      <h4>Impact:</h4>
      <p>Remote code execution.</p>
      <h4>Recommendation:</h4>
      <p>Patch now.</p>
      <h4>More Information:</h4>
      <ul><li>https://example.test/advisory/{code}</li></ul>
    </div>
    """


def paloalto_list_html() -> str:
    rows = [
        ("CVE-2026-0265", "PAN-OS: Authentication Bypass with Cloud Authentication Service (CAS) enabled", "HIGH", "7.2"),
        ("PAN-SA-2026-0007", "Chromium and Prisma Browser: Monthly Vulnerability Update (May 2026)", "MEDIUM", "6.1"),
        ("CVE-2026-0263", "PAN-OS: Remote Code Execution (RCE) in IKEv2 Processing", "HIGH", "7.2"),
        ("CVE-2026-0262", "PAN-OS: Denial of Service Vulnerabilities in Network Traffic Parsing", "MEDIUM", "6.6"),
    ]
    body = "\n".join(
        f"""
        <tr>
          <td><b class="tag CVSS {severity}">{score}</b></td>
          <td><a href="/{code}">{code}\n{title}</a></td>
          <td class="zpad"><div class="vflx"><div>PAN-OS 12.1</div></div></td>
          <td class="zpad"><div class="vflx"><div>&lt; 12.1.4-h5</div></div></td>
          <td class="zpad"><div class="vflx"><div>&gt;= 12.1.4-h5</div></div></td>
          <td><span data-date="2026-05-13T16:00:00.000Z">2026-05-13</span></td>
          <td><span data-date="2026-05-28T21:00:00.000Z">2026-05-28</span></td>
        </tr>
        """
        for code, title, severity, score in rows
    )
    return f"""
    <form id="chartForm">
      <table><tbody>{body}</tbody></table>
      <div>1 - 4 of 4</div>
      <select id="limit"><option value="100" selected>100 per page</option></select>
    </form>
    """


def paloalto_detail_html(code: str) -> str:
    extra_cves = ""
    if code.startswith("PAN-SA-"):
        extra_cves = "<table><tr><td>CVE-2026-4439</td><td>WebGL issue</td></tr><tr><td>CVE-2026-4440</td><td>WebGL issue</td></tr></table>"
    return f"""
    <div id="content">
      <h2>{code} Test Palo Alto Advisory {code}</h2>
      <div class="sa_summary">
        <div class="sa_cvss">
          <div class="tag CVSS HIGH"><span>Urgency HIGHEST</span></div>
          <a class="tag CVSS HIGH" href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Red">Severity 7.2 HIGH</a>
        </div>
        <div class="sa_links">
          <div><small>Published</small><b><span data-date="2026-05-13T16:00:00.000Z">2026-05-13</span></b></div>
          <div><small>Updated</small><b><span data-date="2026-05-28T21:00:00.000Z">2026-05-28</span></b></div>
        </div>
      </div>
      <h3>Description</h3>
      <p>Detail for {code}</p>
      {extra_cves}
      <h3>Product Status</h3>
      <table><tr><th>Versions</th><th>Affected</th><th>Unaffected</th></tr><tr><td>PAN-OS 12.1</td><td>&lt; 12.1.4-h5</td><td>&gt;= 12.1.4-h5</td></tr></table>
      <h3>Solution</h3>
      <p>Upgrade now.</p>
    </div>
    """


def splunk_list_html() -> str:
    rows = [
        ("SVD-2026-0516", "2026-05-20", "Tomcat package updates", "Medium", "Multiple", "Splunk Add-on for Tomcat"),
        ("SVD-2026-0501", "2026-05-01", "Enterprise search injection", "High", "CVE-2026-12345", "Splunk Enterprise"),
        ("SVD-2026-0500", "2026-04-30", "Known advisory", "Low", "NA", "Splunk Enterprise"),
        ("SVD-2026-0401", "2026-04-01", "Older advisory", "Low", "NA", "Splunk Enterprise"),
    ]
    body = "\n".join(
        f"""
        <tr>
          <td><a href="/advisories/{code}">{code}</a></td>
          <td>{date}</td>
          <td>{date}</td>
          <td>{title}</td>
          <td>{severity}</td>
          <td>{cve}</td>
          <td>NA</td>
          <td>NA</td>
          <td>NA</td>
          <td>SPL-{code[-4:]}</td>
          <td>{product}</td>
          <td>9.4.2</td>
          <td>9.4.0</td>
          <td>9.4.0 and earlier</td>
          <td>Search</td>
          <td>{title} description.</td>
          <td>Upgrade.</td>
          <td>None.</td>
          <td>{severity} summary.</td>
          <td>No</td>
          <td>Splunk</td>
        </tr>
        """
        for code, date, title, severity, cve, product in rows
    )
    return f"""
    <table>
      <tr>
        <th>SVD</th><th>Date</th><th>Last Modified</th><th>Title</th><th>Severity</th><th>CVE</th>
        <th>CVSS Vector</th><th>CVSS Score</th><th>CWE</th><th>Bug</th><th>Affected Products</th>
        <th>Fixed Versions</th><th>Affected Versions</th><th>All Affected Versions</th><th>Affected Components</th>
        <th>Description</th><th>Solution</th><th>Mitigations</th><th>Severity Summary</th><th>OSS</th><th>Credit</th>
      </tr>
      {body}
    </table>
    """


def splunk_detail_html(code: str) -> str:
    cve_text = "CVE-2025-68161 and CVE-2025-48924" if code == "SVD-2026-0516" else "CVE-2026-12345"
    return f"""
    <main>
      <h1>Detail {code}</h1>
      <dl>
        <dt>Advisory ID:</dt><dd>{code}</dd>
        <dt>CVE ID:</dt><dd>Multiple</dd>
        <dt>Published:</dt><dd>2026-05-20</dd>
        <dt>Last Update:</dt><dd>2026-05-20</dd>
      </dl>
      <h2>Description</h2>
      <p>Detail includes {cve_text}.</p>
      <table>
        <tr><th>Package</th><th>Remediation</th><th>CVE</th><th>Severity</th></tr>
        <tr><td>tomcat</td><td>Upgrade</td><td>{cve_text.split()[0]}</td><td>Medium</td></tr>
      </table>
      <h2>Product Status</h2>
      <table>
        <tr><th>Product</th><th>Base Version</th><th>Affected Version</th><th>Fix Version</th></tr>
        <tr><td>Splunk Enterprise</td><td>9.4</td><td>9.4.0</td><td>4.0.1</td></tr>
      </table>
      <h2>Solution</h2>
      <p>Upgrade now.</p>
    </main>
    """


def hikvision_list_html() -> str:
    rows = [
        ("hsrc-2026-0003", "HSRC-2026-0003: New Hikvision Access Control Vulnerability", "High", "2026-06-03"),
        ("hsrc-2026-0002", "HSRC-2026-0002: Known Hikvision Camera Vulnerability", "Medium", "2026-06-02"),
        ("hsrc-2026-0001", "HSRC-2026-0001: Older Hikvision NVR Vulnerability", "Low", "2026-06-01"),
    ]
    body = "\n".join(
        f"""
        <div class="security-advisory item">
          <a href="/hk/support/cybersecurity/security-advisory/{code}/">{title}</a>
          <time>{date}</time>
          <span>Severity: {severity}</span>
        </div>
        """
        for code, title, severity, date in rows
    )
    return f"<main><p>Total 3 security advisories</p>{body}</main>"


def hikvision_detail_html(code: str) -> str:
    return f"""
    <article>
      <h1>{code.upper()}: Hikvision Security Advisory</h1>
      <p>Published Date: 2026-06-03</p>
      <p>Severity: High</p>
      <p>CVE-2026-{code[-4:]} affects a Hikvision product.</p>
      <h2>Description</h2>
      <p>Detail for {code}.</p>
      <h2>Affected Products</h2>
      <ul><li>Product {code}</li></ul>
      <h2>Solution</h2>
      <p>Upgrade firmware.</p>
    </article>
    """


def cnnvd_list_payload() -> dict:
    return {
        "code": 200,
        "success": True,
        "data": {
            "total": 3,
            "pageSize": 10,
            "records": [
                {
                    "id": "record-1911",
                    "vulName": "Google Chrome 安全漏洞",
                    "cnnvdId": "CNNVD-202606-1911",
                    "cveId": "CVE-2026-11628",
                    "vulLevel": "High",
                    "publishDate": "2026-06-08",
                    "vulTypeName": "其他",
                },
                {
                    "id": "record-1910",
                    "vulName": "Google Chrome 释放后重用漏洞",
                    "cnnvdId": "CNNVD-202606-1910",
                    "cveId": "CVE-2026-11629",
                    "vulLevel": "Medium",
                    "publishDate": "2026-06-08",
                    "vulTypeName": "其他",
                },
                {
                    "id": "record-1909",
                    "vulName": "Older vulnerability",
                    "cnnvdId": "CNNVD-202606-1909",
                    "publishDate": "2026-06-07",
                },
            ],
        },
    }


def cnnvd_detail_payload(record_id: str) -> dict:
    return {
        "code": 200,
        "success": True,
        "data": {
            "id": record_id,
            "vulName": "Google Chrome 安全漏洞",
            "cnnvdId": "CNNVD-202606-1911",
            "cveId": "CVE-2026-11628",
            "vulLevel": "High",
            "vulTypeName": "其他",
            "publishDate": "2026-06-08",
            "vulDesc": "Chrome vulnerability.",
            "productName": "Google Chrome",
            "officialPatchLink": "https://example.test/patch",
        },
    }


def cnvd_list_html() -> str:
    rows = [
        ("2026-21550", "Example Product 远程代码执行漏洞", "高", "2026-06-01"),
        ("2026-21549", "Example Service 信息泄露漏洞", "中", "2026-05-31"),
        ("2026-21548", "Older Product 越权漏洞", "低", "2026-05-30"),
    ]
    body = "\n".join(
        f"""
        <tr>
          <td><a href="/flaw/show/CNVD-{code}">{title}</a></td>
          <td>{severity}</td>
          <td>10</td>
          <td>0</td>
          <td>1</td>
          <td>{date}</td>
        </tr>
        """
        for code, title, severity, date in rows
    )
    return f"""
    <table>
      <tr><th>漏洞标题</th><th>危害级别</th><th>点击</th><th>评论</th><th>关注</th><th>公开日期</th></tr>
      {body}
    </table>
    <div>共 3 条</div>
    """


def hkcert_list_html(page: int) -> str:
    page_codes = {
        1: ["p1-a", "p1-b"],
        2: ["p2-a", "p2-b"],
        3: ["p3-a", "p3-b"],
    }
    cards = "".join(
        f'<a class="listingcard__item" href="/security-bulletin/{code}">'
        f'<p class="listingcard__title">{code}</p></a>'
        for code in page_codes[page]
    )
    pages = "".join(
        f'<a href="/security-bulletin?item_per_page=10&amp;page={index}">{index}</a>'
        for index in range(1, 4)
    )
    return f"<html><body>{cards}{pages}</body></html>"


def hkcert_detail_html(code: str) -> str:
    return f"""
    <html><body>
      <h1 class="page-title page-title--inner">{code}</h1>
      <div class="page-intro"><div class="ckec"><p>Intro for {code}</p></div></div>
    </body></html>
    """


def cnvd_detail_html(code: str) -> str:
    return f"""
    <h1>Example CNVD Detail {code}</h1>
    <table>
      <tr><th>CNVD编号</th><td>CNVD-{code}</td></tr>
      <tr><th>漏洞名称</th><td>Example CNVD Detail {code}</td></tr>
      <tr><th>危害级别</th><td>高 CVSS: 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td></tr>
      <tr><th>CVE ID</th><td>CVE-2026-12345</td></tr>
      <tr><th>影响产品</th><td>Product {code}</td></tr>
      <tr><th>漏洞描述</th><td>Detail for CVE-2026-12345</td></tr>
      <tr><th>漏洞解决方案</th><td>Patch now.</td></tr>
      <tr><th>公开日期</th><td>2026-06-01</td></tr>
    </table>
    <a href="https://example.test/cnvd/{code}">Reference</a>
    """


def juniper_list_coveo_payload(*, first_result: int = 0, per_page: int = 10) -> dict:
    all_codes = [f"JSA{93456 - index}" for index in range(25)]
    page_codes = all_codes[first_result : first_result + per_page]
    results = [
        {
            "title": f"{code}: Junos OS advisory",
            "raw": {
                "sfcec_documentid__c": code,
                "sftitle": f"{code}: Junos OS advisory",
                "sfrecordtypename": "Security Advisories",
                "sflastpublisheddate": "2026-05-29",
                "sfcustomer_url__c": f"https://supportportal.juniper.net/s/article/{code}",
                "sfurlname": code,
            },
        }
        for code in page_codes
    ]
    return {"totalCount": len(all_codes), "results": results}


def juniper_detail_coveo_payload(slug: str) -> dict:
    code = slug if slug.upper().startswith("JSA") else "JSA93456"
    return {
        "results": [
            {
                "title": f"{code}: Junos OS Security Advisory",
                "raw": {
                    "sfcec_documentid__c": code,
                    "sftitle": f"{code}: Junos OS Security Advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sfcustomer_url__c": f"https://supportportal.juniper.net/s/article/{slug}",
                    "sfcec_problem__c": f"Detail includes CVE-2026-55555 for {code}.",
                    "sfcec_product_affected__c": "Junos OS",
                    "sfcec_solution__c": "Upgrade Junos OS.",
                },
            }
        ]
    }


def cve_delta_batch(
    fetch_time: str,
    *,
    new: list[str] | None = None,
    updated: list[str] | None = None,
    deleted: list[str] | None = None,
    date_updated: str = "2026-06-05T00:00:00.000Z",
) -> dict:
    return {
        "fetchTime": fetch_time,
        "new": [cve_delta_entry(cve_id, date_updated=date_updated) for cve_id in new or []],
        "updated": [cve_delta_entry(cve_id, date_updated=date_updated) for cve_id in updated or []],
        "deleted": [cve_delta_entry(cve_id, include_link=False) for cve_id in deleted or []],
    }


def cve_delta_entry(cve_id: str, *, include_link: bool = True, date_updated: str = "2026-06-05T00:00:00.000Z") -> dict:
    return {
        "cveId": cve_id,
        "cveOrgLink": f"https://www.cve.org/CVERecord?id={cve_id}",
        "githubLink": f"https://example.test/{cve_id}.json" if include_link else None,
        "dateUpdated": date_updated,
    }


def cve_v5_record(cve_id: str, *, date_updated: str = "2026-06-05T00:00:00.000Z") -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerShortName": "example",
            "state": "PUBLISHED",
            "datePublished": date_updated,
            "dateUpdated": date_updated,
        },
        "containers": {
            "cna": {
                "title": f"Title {cve_id}",
                "descriptions": [{"lang": "en", "value": f"Description {cve_id}"}],
                "affected": [
                    {
                        "vendor": "Example",
                        "product": "Widget",
                        "versions": [{"status": "affected", "version": "1.0"}],
                    }
                ],
                "metrics": [],
                "problemTypes": [],
                "references": [{"url": f"https://example.test/advisory/{cve_id}"}],
            }
        },
    }


def fake_mongo_factory(collection: "FakeMongoCollection"):
    def create_client(uri: str) -> "FakeMongoClient":
        return FakeMongoClient(collection)

    return create_client


def identities(records: list[dict]) -> list[str]:
    return [f"{record['type']}:{record['code']}" for record in records]


class FakeMongoClient:
    def __init__(self, collection: "FakeMongoCollection") -> None:
        self.collection = collection
        self.closed = False

    def __getitem__(self, name: str) -> "FakeMongoDatabase":
        return FakeMongoDatabase(self.collection)

    def close(self) -> None:
        self.closed = True


class FakeMongoDatabase:
    def __init__(self, collection: "FakeMongoCollection") -> None:
        self.collection = collection

    def __getitem__(self, name: str) -> "FakeMongoCollection":
        return self.collection


class FakeMongoCollection:
    def __init__(
        self,
        documents: dict[str, dict] | None = None,
        *,
        fail_insert_once_for: str | None = None,
    ) -> None:
        self.documents = copy.deepcopy(documents or {})
        self.indexes: list[tuple[str, bool]] = []
        self.fail_insert_once_for = fail_insert_once_for

    def create_index(self, field: str, unique: bool = False) -> None:
        self.indexes.append((field, unique))

    def find(self, query: dict | None = None, projection: dict | None = None):
        query = query or {}
        if query:
            return []
        return [copy.deepcopy(document) for document in self.documents.values()]

    def find_one(self, query: dict) -> dict | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def insert_one(self, document: dict) -> None:
        if document["_id"] == self.fail_insert_once_for:
            self.fail_insert_once_for = None
            raise RuntimeError(f"simulated insert failure for {document['_id']}")
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)

    def delete_one(self, query: dict):
        deleted = int(query["_id"] in self.documents)
        self.documents.pop(query["_id"], None)
        return FakeDeleteResult(deleted)


class FakeDeleteResult:
    def __init__(self, deleted_count: int) -> None:
        self.deleted_count = deleted_count
