from pathlib import Path

from vuln_scraper.scrapers.hikvision.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.hikvision.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_hikvision_list_extracts_advisories() -> None:
    page = parse_advisory_list((FIXTURES / "list.html").read_text(encoding="utf-8"), page=1)

    assert page.total_records == 2
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "hikvision:hsrc-2026-0001"
    assert first.display_id == "HIKVISION-hsrc-2026-0001"
    assert first.title == "HSRC-2026-0001: Hikvision Camera Command Injection Vulnerability"
    assert first.status == "High"
    assert first.disclosure_date == "2026-05-28"
    assert first.embedded_detail["severity"] == "High"
    assert first.embedded_detail["reference_links"][0].endswith("/hsrc-2026-0001/")


def test_parse_hikvision_list_extracts_content_advisory_links() -> None:
    page = parse_advisory_list((FIXTURES / "list_content.html").read_text(encoding="utf-8"), page=1)

    assert len(page.entries) == 1
    entry = page.entries[0]
    assert entry.key == "hikvision:security-vulnerabilities-in-hikvision-nvr-devices"
    assert entry.title == "Security Vulnerabilities in Hikvision NVR Devices"
    assert entry.embedded_detail["reference_links"][0].endswith(
        "security-vulnerabilities-in-hikvision-nvr-devices.html"
    )


def test_parse_hikvision_detail_extracts_sections_and_cves() -> None:
    detail = parse_detail_page((FIXTURES / "detail.html").read_text(encoding="utf-8")).to_dict()

    assert detail["advisory_id"] == "HSRC-2026-0001"
    assert detail["published_date"] == "2026-05-28"
    assert detail["updated_date"] == "2026-05-30"
    assert detail["severity"] == "High"
    assert detail["cve_ids"] == ["CVE-2026-45678"]
    assert detail["affected_products"] == ["DS-2CD Camera firmware before 5.7.20"]
    assert "Upgrade to firmware" in detail["solution"]
