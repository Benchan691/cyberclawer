from pathlib import Path

from vuln_scraper.scrapers.fortiguard.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.fortiguard.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_fortiguard_list_extracts_rows_and_pagination() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_advisory_list(html, page=1)

    assert page.total_records == 724
    assert page.total_pages == 49
    assert len(page.entries) == 2

    first = page.entries[0]
    assert first.key == "fortiguard:FG-IR-26-158"
    assert first.display_id == "FORTIGUARD-FG-IR-26-158"
    assert first.title == "Broken access control in the RADIUS type admin group"
    assert first.status == "High"
    assert first.disclosure_date is not None
    assert "FortiOS" in (first.vuln_type or "") or first.embedded_detail.get("products")
    assert first.embedded_detail["advisory_id"] == "FG-IR-26-158"
    assert first.embedded_detail["cve_ids"]

    second = page.entries[1]
    assert second.key == "fortiguard:FG-IR-26-157"
    assert second.title == "Content-Encoding WAF Evasion"


def test_parse_fortiguard_detail_extracts_fields_and_csaf_url() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["advisory_id"] == "FG-IR-26-160"
    assert detail["title"] == "FGFM Authentication Weakening via CLI Configuration"
    assert detail["severity"] == "High"
    assert detail["component"] == "OTHERS"
    assert detail["discovered"] == "Internal"
    assert detail["attack_type"] == "Unauthenticated"
    assert detail["known_exploited"] == "No"
    assert detail["impact"] == "Improper access control"
    assert detail["published_date"] == "2026-08-12"
    assert detail["cvss_score"] == 7.3
    assert detail["cvss_vector"]
    assert detail["cve_ids"] == ["CVE-2026-70468"]
    assert detail["summary"]
    assert detail["timeline"][0]["date"] == "2026-08-12"
    assert detail["affected_products"][0]["version"] == "FortiManager 8.0"
    assert detail["cvrf_url"] == "https://www.fortiguard.com/psirt/cvrf/FG-IR-26-160"
    assert detail["csaf_url"] == (
        "https://filestore.fortinet.com/fortiguard/psirt/"
        "csaf_fgfm-authentication-weakening-via-cli-configuration_fg-ir-26-160.json"
    )
    assert detail["csaf"] is None
