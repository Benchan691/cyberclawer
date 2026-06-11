from pathlib import Path

from vuln_scraper.scrapers.splunk.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.splunk.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_splunk_list_maps_rows_and_embedded_detail() -> None:
    page = parse_advisory_list((FIXTURES / "list.html").read_text(encoding="utf-8"), page=1)

    assert page.total_pages == 1
    assert page.total_records == 3
    first = page.entries[0]
    assert first.identity.type == "SPLUNK"
    assert first.identity.code == "SVD-2026-0516"
    assert first.title.startswith("Third-Party Package Updates")
    assert first.vuln_type == "Splunk Add-on for Tomcat"
    assert first.disclosure_date == "2026-05-20"
    assert first.status == "Medium"
    assert first.embedded_detail["cve_ids"] == ["CVE-2025-68161"]
    assert page.entries[2].embedded_detail["cve_ids"] == []
    assert page.entries[2].to_record(page.entries[2].embedded_detail)["cve_code"] is None


def test_splunk_list_entry_to_record_uses_primary_cve_code() -> None:
    page = parse_advisory_list((FIXTURES / "list.html").read_text(encoding="utf-8"), page=1)
    record = page.entries[1].to_record(page.entries[1].embedded_detail)

    assert record["type"] == "splunk"
    assert record["code"] == "SVD-2026-0501"
    assert record["cve_code"] == "2026-12345"
    assert "cross_refs" not in record


def test_parse_splunk_detail_extracts_sections_and_tables() -> None:
    detail = parse_detail_page((FIXTURES / "detail.html").read_text(encoding="utf-8")).to_dict()

    assert detail["advisory_id"] == "SVD-2026-0516"
    assert detail["published_date"] == "2026-05-20"
    assert detail["last_modified"] == "2026-05-20"
    assert detail["cve_ids"] == ["CVE-2025-68161", "CVE-2025-48924"]
    assert detail["cve_id"] == "CVE-2025-68161"
    assert "Several package updates" in detail["description"]
    assert len(detail["description_tables"]) == 1
    assert detail["description_tables"][0]["headers"] == ["package", "remediation", "cve", "severity"]
    assert detail["description_tables"][0]["rows"][0]["package"] == "commons-lang3"
    assert detail["packages"][0]["package"] == "commons-lang3"
    assert detail["product_status"][0]["fix_version"] == "4.0.1"
