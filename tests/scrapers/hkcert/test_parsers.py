from pathlib import Path

from vuln_scraper.scrapers.hkcert.parsers.detail import normalize_hkcert_detail, parse_detail_page
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
    assert detail["systems_affected"] == ["Android 13", "Android 14", "Android 15"]
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
    assert "views" not in detail
    assert detail["table"] == []


def test_parse_detail_page_extracts_intro_product_table() -> None:
    html = (FIXTURES / "detail_product_table.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["intro"] is None
    assert len(detail["table"]) == 2

    premiere = detail["table"][0]
    assert premiere["name"] == "Adobe Premiere Pro"
    assert premiere["risk_level"] == "Medium Risk"
    assert premiere["impacts"] == "Remote Code Execution"
    assert premiere["details"] == "APSB26-46"
    assert premiere["details_url"] == (
        "https://helpx.adobe.com/security/products/premiere_pro/apsb26-46.html"
    )

    commerce = detail["table"][1]
    assert commerce["name"] == "Adobe Commerce"
    assert "Security Restriction Bypass" in commerce["impacts"]
    assert "Data Manipulation" in commerce["impacts"]
    assert commerce["details"] == "APSB26-49"
    assert commerce["details_url"] == (
        "https://helpx.adobe.com/security/products/magento/apsb26-49.html"
    )
    assert detail["summary"] == "Adobe Premiere Pro\nAdobe Commerce"


def test_normalize_hkcert_detail_converts_legacy_intro_tables() -> None:
    normalized = normalize_hkcert_detail(
        {
            "intro": "Adobe Premiere Pro Medium Risk Remote Code Execution APSB26-46",
            "views": "1004",
            "intro_tables": [
                {
                    "headers": ["vulnerable_product", "risk_level", "impacts", "notes", "details"],
                    "rows": [
                        {
                            "vulnerable_product": "Adobe Premiere Pro",
                            "risk_level": "Medium Risk",
                            "impacts": "Remote Code Execution",
                            "details": "APSB26-46",
                        }
                    ],
                }
            ],
        }
    )

    assert "intro_tables" not in normalized
    assert "views" not in normalized
    assert normalized["table"] == [
        {
            "name": "Adobe Premiere Pro",
            "risk_level": "Medium Risk",
            "impacts": "Remote Code Execution",
            "details": "APSB26-46",
        }
    ]


def test_normalize_hkcert_detail_migrates_legacy_vulnerable_products() -> None:
    normalized = normalize_hkcert_detail(
        {
            "vulnerable_products": [
                {
                    "vulnerable_product": "Adobe Commerce",
                    "risk_level": "High Risk",
                    "details": "APSB26-49",
                }
            ],
        }
    )

    assert "vulnerable_products" not in normalized
    assert normalized["table"] == [
        {
            "name": "Adobe Commerce",
            "risk_level": "High Risk",
            "details": "APSB26-49",
        }
    ]
