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
    assert detail["title"] == "HSRC-2026-0001: Hikvision Camera Command Injection Vulnerability"
    assert detail["published_date"] == "2026-05-28"
    assert detail["updated_date"] == "2026-05-30"
    assert detail["severity"] == "High"
    assert detail["cve_ids"] == ["CVE-2026-45678"]
    assert detail["affected_products"] == ["DS-2CD Camera firmware before 5.7.20"]
    assert "Upgrade to firmware" in detail["solution"]
    assert "A command injection vulnerability affects selected Hikvision camera firmware." in detail["summary"]
    assert "CVE-2026-45678 allows authenticated command injection." not in detail["summary"]


def test_parse_hikvision_detail_summary_falls_back_without_aem_markup() -> None:
    html = """
    <article>
      <h1>HSRC-2026-0002: Fallback Advisory</h1>
      <p>Short line.</p>
      <p>This is a longer fallback summary paragraph for advisories without AEM markup.</p>
    </article>
    """
    detail = parse_detail_page(html).to_dict()

    assert detail["title"] == "HSRC-2026-0002: Fallback Advisory"
    assert detail["summary"] == (
        "This is a longer fallback summary paragraph for advisories without AEM markup."
    )


def test_parse_hikvision_detail_structured_hikcentral_advisory() -> None:
    detail = parse_detail_page(
        (FIXTURES / "detail_hikcentral.html").read_text(encoding="utf-8")
    ).to_dict()

    assert detail["advisory_id"] == "HSRC-202410-01"
    assert detail["sn_no"] == "HSRC-202410-01"
    assert detail["edit"] == "Hikvision Security Response Center (HSRC)"
    assert detail["initial_release_date"] == "2024-10-18"
    assert detail["published_date"] == "2024-10-18"
    assert detail["cve_ids"] == ["CVE-2024-47485", "CVE-2024-47486", "CVE-2024-47487"]
    assert "CVE ID" not in (detail["summary"] or "")
    assert "CSV injection vulnerability" in detail["summary"]
    assert "SQL injection vulnerability" in detail["summary"]
    assert len(detail["scoring"]) == 3
    assert detail["scoring"][0]["cve_id"] == "CVE-2024-47485"
    assert detail["scoring"][0]["base_score"] == "5.5"
    assert detail["scoring"][2]["cve_id"] == "CVE-2024-47487"
    assert detail["scoring"][2]["base_score"] == "7.2"
    assert len(detail["affected_versions_and_fix"]) == 3
    assert detail["affected_versions_and_fix"][0] == {
        "Product Name": "HikCentral Master Lite",
        "CVE ID": "CVE-2024-47485",
        "Affected Versions": "Versions between V2.0.0 and V2.2.1",
        "Fixed Version": "V2.3.0",
    }
    assert any("HikCentral Master Lite" in item for item in detail["affected_products"])
