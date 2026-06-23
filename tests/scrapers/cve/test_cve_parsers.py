from datetime import datetime, time
from zoneinfo import ZoneInfo

from vuln_scraper.scrapers import CVEProvider
from vuln_scraper.scrapers.cve.parsers.detail import parse_cve_detail_response
from vuln_scraper.scrapers.cve.parsers.list import (
    parse_cve_delta_log,
    parse_cve_list,
    parse_cve_list_updated_since,
)

LOCAL_TIMEZONE = ZoneInfo("Asia/Hong_Kong")


def test_parse_delta_log_filters_and_orders_batches_oldest_first() -> None:
    payload = [
        delta_batch(
            "2026-06-05T03:00:00.000Z",
            updated=[delta_entry("CVE-2026-3000")],
        ),
        delta_batch(
            "2026-06-05T01:00:00.000Z",
            new=[delta_entry("CVE-2026-1000")],
        ),
        delta_batch(
            "2026-06-05T02:00:00.000Z",
            deleted=[delta_entry("CVE-2026-2000", github_link=None)],
        ),
    ]

    batches = parse_cve_delta_log(payload, after="2026-06-05T01:30:00.000Z")

    assert [batch.fetch_time for batch in batches] == [
        "2026-06-05T02:00:00.000Z",
        "2026-06-05T03:00:00.000Z",
    ]
    assert batches[0].entries[0].action == "deleted"
    assert batches[0].entries[0].identity == "cve:2026-2000"
    assert batches[1].entries[0].action == "updated"


def test_parse_cve_list_exposes_non_deleted_delta_entries() -> None:
    page = parse_cve_list(
        [
            delta_batch(
                "2026-06-05T03:00:00.000Z",
                new=[delta_entry("CVE-2026-3000")],
                deleted=[delta_entry("CVE-2026-2000", github_link=None)],
            )
        ],
        page=1,
    )

    assert page.total_pages == 1
    assert page.total_records == 1
    assert [entry.key for entry in page.entries] == ["cve:2026-3000"]
    assert page.entries[0].embedded_detail["_delta_action"] == "new"


def test_parse_cve_list_updated_since_filters_by_today_boundary() -> None:
    today = datetime.now(LOCAL_TIMEZONE).date()
    yesterday = today.fromordinal(today.toordinal() - 1)
    today_updated = f"{today.isoformat()}T12:00:00.000Z"
    yesterday_updated = f"{yesterday.isoformat()}T12:00:00.000Z"
    boundary = datetime.combine(today, time.min, tzinfo=LOCAL_TIMEZONE)
    payload = [
        delta_batch(
            "2026-06-05T03:00:00.000Z",
            new=[delta_entry("CVE-2026-3000", date_updated=today_updated)],
        ),
        delta_batch(
            "2026-06-05T02:00:00.000Z",
            updated=[delta_entry("CVE-2026-2000", date_updated=yesterday_updated)],
        ),
    ]

    page = parse_cve_list_updated_since(payload, updated_since=boundary, page=1)

    assert [entry.key for entry in page.entries] == ["cve:2026-3000"]


def test_parse_cve_v5_normalizes_details_without_raw_dupes() -> None:
    payload = cve_record("CVE-2026-48907")

    detail = parse_cve_detail_response(payload).to_dict()

    assert detail["cve_id"] == "CVE-2026-48907"
    assert detail["title"] == "Joomla remote code execution"
    assert detail["published"] == "2026-06-05T07:31:30.257Z"
    assert detail["last_modified"] == "2026-06-05T07:31:30.257Z"
    assert detail["vuln_status"] == "PUBLISHED"
    assert detail["descriptions"][0]["value"] == "A remote code execution vulnerability."
    assert detail["metrics"]["cvss_v40"][0]["cvssData"]["baseSeverity"] == "CRITICAL"
    assert detail["weaknesses"][0]["descriptions"][0]["cweId"] == "CWE-284"
    assert detail["references"] == [{"url": "https://example.test/advisory"}]
    assert detail["affected"][0]["product"] == "Joomla Extension"
    assert "affected_products" not in detail
    assert "raw" not in detail


def test_parse_cve_v5_accepts_missing_optional_containers() -> None:
    payload = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-2026-1000",
            "state": "RESERVED",
        },
        "containers": {},
    }

    detail = parse_cve_detail_response(payload).to_dict()

    assert detail["cve_id"] == "CVE-2026-1000"
    assert detail["descriptions"] == []
    assert detail["metrics"] == {}
    assert "affected_products" not in detail


def test_provider_builds_cvelist_v5_urls_and_normalized_entry() -> None:
    provider = CVEProvider()

    assert provider.list_url(1).endswith("/cves/deltaLog.json")
    assert provider.cve_url("CVE-2026-48907").endswith(
        "/cves/2026/48xxx/CVE-2026-48907.json"
    )

    entry = provider.entry_from_record(
        cve_record("CVE-2026-48907"),
        detail_url=provider.cve_url("CVE-2026-48907"),
    )
    record = entry.to_record(entry.embedded_detail, detail_url=provider.cve_url(entry.display_id))

    assert entry.key == "cve:2026-48907"
    assert record["type"] == "cve"
    assert record["code"] == "2026-48907"
    assert record["cve_code"] is None
    assert "raw" not in record["details"]["cve"]


def delta_batch(
    fetch_time: str,
    *,
    new: list[dict] | None = None,
    updated: list[dict] | None = None,
    deleted: list[dict] | None = None,
) -> dict:
    return {
        "fetchTime": fetch_time,
        "new": new or [],
        "updated": updated or [],
        "deleted": deleted or [],
    }


def delta_entry(cve_id: str, *, github_link: str | None = "https://example.test/cve.json", date_updated: str = "2026-06-05T00:00:00.000Z") -> dict:
    return {
        "cveId": cve_id,
        "cveOrgLink": f"https://www.cve.org/CVERecord?id={cve_id}",
        "githubLink": github_link,
        "dateUpdated": date_updated,
    }


def cve_record(cve_id: str, *, title: str = "Joomla remote code execution") -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerShortName": "example",
            "state": "PUBLISHED",
            "datePublished": "2026-06-05T07:31:30.257Z",
            "dateUpdated": "2026-06-05T07:31:30.257Z",
        },
        "containers": {
            "cna": {
                "title": title,
                "descriptions": [
                    {"lang": "en", "value": "A remote code execution vulnerability."}
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Joomla Extension",
                        "defaultStatus": "unaffected",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "1.0",
                                "lessThan": "2.0",
                                "versionType": "semver",
                            }
                        ],
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "cvssV4_0": {
                            "version": "4.0",
                            "baseScore": 10,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "type": "CWE",
                                "cweId": "CWE-284",
                                "description": "Improper Access Control",
                            }
                        ]
                    }
                ],
                "references": [{"url": "https://example.test/advisory"}],
            }
        },
    }
