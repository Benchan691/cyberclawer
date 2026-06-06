import asyncio
import copy
from urllib.parse import parse_qs, urlparse

import pytest

from vuln_scraper.client import FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers.cisco import CiscoProvider
from vuln_scraper.scrapers.cnnvd import CNNVDProvider
from vuln_scraper.scrapers.cnvd import CNVDProvider
from vuln_scraper.scrapers.cve import CVEProvider
from vuln_scraper.scrapers.govcert import GovCERTProvider
from vuln_scraper.scrapers.hkcert import HKCERTProvider
from vuln_scraper.scrapers.hikvision import HikvisionProvider
from vuln_scraper.scrapers.huawei_sa import HuaweiSAProvider
from vuln_scraper.scrapers.infosec import InfoSecProvider
from vuln_scraper.scrapers.juniper import JuniperProvider
from vuln_scraper.scrapers.paloalto import PaloAltoProvider
from vuln_scraper.scrapers.ransomwarelive import RansomwareLiveProvider
from vuln_scraper.scrapers.splunk import SplunkProvider
from vuln_scraper.scrapers.zeroday import ZeroDayProvider

from tests.fake_avd_provider import FakeAvdProvider


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

    asyncio.run(ScraperRunner(settings, provider=FakeAvdProvider())._run_with_client(client))

    assert settings.output_file.exists()


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
    known_id = "0f9ea9d7144547dcaf6374acae1c7b97"
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

    assert identities(output["vulnerabilities"]) == ["cnnvd:c0f1edb8b3ae4d0fbb65714730d63dde"]
    assert output["mongo_sync"]["inserted"] == 1
    assert client.detail_ids_seen == ["c0f1edb8b3ae4d0fbb65714730d63dde"]


def test_cnnvd_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeCNNVDClient()
    known_id = "c0f1edb8b3ae4d0fbb65714730d63dde"
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

    assert identities(output["vulnerabilities"]) == ["cnnvd:0f9ea9d7144547dcaf6374acae1c7b97"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-12345"
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {
        "cnnvd:0f9ea9d7144547dcaf6374acae1c7b97",
        f"cnnvd:{known_id}",
    }
    assert client.detail_ids_seen == ["0f9ea9d7144547dcaf6374acae1c7b97"]


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


class FakeCVEClient:
    def __init__(self, *, delta: list[dict] | None = None) -> None:
        self.delta = delta or []
        self.urls_seen: list[str] = []
        self.detail_ids_seen: list[str] = []

    async def get_json(self, url: str, *, headers=None):
        self.urls_seen.append(url)
        if url.endswith("/deltaLog.json"):
            return FakeJSONResult(self.delta, url)
        cve_id = url.rsplit("/", 1)[-1].removesuffix(".json")
        self.detail_ids_seen.append(cve_id)
        return FakeJSONResult(cve_v5_record(cve_id), url)


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
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def request_json(self, method: str, url: str, *, headers=None, json_body=None, data=None):
        if url.endswith("/vulWarnList"):
            return FakeJSONResult(cnnvd_list_payload(), url)

        code = dict(data or {})["warnId"]
        self.detail_ids_seen.append(code)
        return FakeJSONResult(cnnvd_detail_payload(code), url)


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
            "pageSize": 100,
            "records": [
                {
                    "warnId": "0f9ea9d7144547dcaf6374acae1c7b97",
                    "warnName": "【漏洞通报】CNNVD关于OpenClaw多个安全漏洞的通报",
                    "publishTime": "2026-05-20 14:27:51",
                    "createUname": "zhangdan",
                },
                {
                    "warnId": "c0f1edb8b3ae4d0fbb65714730d63dde",
                    "warnName": "【漏洞通报】CNNVD关于微软多个安全漏洞的通报",
                    "publishTime": "2026-05-14 14:30:56",
                    "createUname": "lixia",
                },
                {
                    "warnId": "older",
                    "warnName": "【漏洞通报】CNNVD关于旧漏洞的通报",
                    "publishTime": "2026-05-01 10:00:00",
                },
            ],
        },
    }


def cnnvd_detail_payload(code: str) -> dict:
    return {
        "code": 200,
        "success": True,
        "data": {
            "warnId": code,
            "warnName": "【漏洞通报】CNNVD关于OpenClaw多个安全漏洞的通报",
            "publishTime": "2026-05-20 14:27:51",
            "createUname": "zhangdan",
            "enclosureContent": (
                "<p>Detail includes CVE-2026-12345.</p>"
                "<p><strong>一、漏洞介绍</strong></p><p>OpenClaw issue.</p>"
                "<p><strong>二、修复建议</strong></p><p>Upgrade now.</p>"
            ),
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
) -> dict:
    return {
        "fetchTime": fetch_time,
        "new": [cve_delta_entry(cve_id) for cve_id in new or []],
        "updated": [cve_delta_entry(cve_id) for cve_id in updated or []],
        "deleted": [cve_delta_entry(cve_id, include_link=False) for cve_id in deleted or []],
    }


def cve_delta_entry(cve_id: str, *, include_link: bool = True) -> dict:
    return {
        "cveId": cve_id,
        "cveOrgLink": f"https://www.cve.org/CVERecord?id={cve_id}",
        "githubLink": f"https://example.test/{cve_id}.json" if include_link else None,
        "dateUpdated": "2026-06-05T00:00:00.000Z",
    }


def cve_v5_record(cve_id: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerShortName": "example",
            "state": "PUBLISHED",
            "datePublished": "2026-06-05T00:00:00.000Z",
            "dateUpdated": "2026-06-05T00:00:00.000Z",
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
