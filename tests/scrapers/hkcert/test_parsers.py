from pathlib import Path

from vuln_scraper.scrapers.hkcert.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.hkcert.parsers.list import parse_security_bulletin_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_security_bulletin_list_extracts_identity_and_metadata() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_security_bulletin_list(
        html,
        page=1,
        provider="hkcert",
        source_url="https://www.hkcert.org/security-bulletin",
    )

    assert page.total_pages == 2
    assert len(page.entries) == 1
    entry = page.entries[0]
    assert entry.identity.type == "HKCERT"
    assert entry.identity.code == "android-multiple-vulnerabilities_20250601"
    assert entry.title == "Android Multiple Vulnerabilities"
    assert entry.status == "NEW"
    assert entry.disclosure_date == "1 Jun 2026"


def test_parse_detail_page_extracts_required_hkcert_sections() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["intro"] == (
        "Multiple vulnerabilities were identified in Android.\n"
        "Note: CVE-2025-48595 is being exploited in the wild."
    )
    assert detail["note"] == "Note: CVE-2025-48595 is being exploited in the wild."
    assert "Remote Code Execution" in detail["impact"]
    assert detail["systems_affected"] == "Android 13, Android 14 and Android 15"
    assert "Apply fixes issued by the vendor" in detail["solutions"]
    assert detail["solution_links"] == ["https://source.android.com/security/bulletin/2025-06-01"]
    assert detail["vulnerability_identifiers"] == [
        {"cve_id": "CVE-2025-48595"},
        {"cve_id": "CVE-2025-48633"},
    ]
    assert detail["bulletin_source"] == "Android"
    assert detail["related_links"] == ["https://source.android.com/security/bulletin/2025-06-01"]
    assert detail["risk_level"] == "Medium Risk"
    assert detail["release_date"] == "1 Jun 2026"
    assert detail["last_update_date"] == "2 Jun 2026"
    assert detail["views"] == "1004"
