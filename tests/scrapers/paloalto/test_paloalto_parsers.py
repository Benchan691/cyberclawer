from pathlib import Path

from vuln_scraper.scrapers.paloalto.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.paloalto.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_paloalto_list_extracts_rows_and_pagination() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_advisory_list(html, page=1)

    assert page.total_records == 527
    assert page.total_pages == 6
    assert len(page.entries) == 2

    first = page.entries[0]
    assert first.key == "paloalto:CVE-2026-0265"
    assert first.display_id == "PALOALTO-CVE-2026-0265"
    assert first.title == "PAN-OS: Authentication Bypass with Cloud Authentication Service (CAS) enabled"
    assert first.status == "HIGH"
    assert first.vuln_type == "Cloud NGFW, PAN-OS 12.1, Prisma Access"
    assert first.disclosure_date == "2026-05-13"
    assert first.embedded_detail["cvss_score"] == 7.2
    assert first.embedded_detail["updated_date"] == "2026-05-28"
    assert first.embedded_detail["cve_ids"] == ["CVE-2026-0265"]

    second = page.entries[1]
    assert second.key == "paloalto:PAN-SA-2026-0007"
    assert second.status == "MEDIUM"
    assert second.embedded_detail["cve_ids"] == []


def test_parse_paloalto_detail_extracts_cve_advisory_fields() -> None:
    html = (FIXTURES / "detail_cve.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["advisory_id"] == "CVE-2026-0265"
    assert detail["title"] == "PAN-OS: Authentication Bypass with Cloud Authentication Service (CAS) enabled"
    assert detail["severity"] == "HIGH"
    assert detail["urgency"] == "HIGHEST"
    assert detail["cvss_score"] == 7.2
    assert detail["cvss_vector"].startswith("CVSS:4.0/AV:N")
    assert detail["published_date"] == "2026-05-13"
    assert detail["updated_date"] == "2026-05-28"
    assert detail["discovered"] == "externally"
    assert detail["cve_ids"] == ["CVE-2026-0265"]
    assert detail["products"] == ["PAN-OS 12.1", "Prisma Access"]
    assert detail["product_status"][0]["affected"] == "< 12.1.4-h5\n< 12.1.7"
    assert detail["weakness"] == [
        {
            "id": "CWE-347",
            "name": "CWE-347 Improper Verification of Cryptographic Signature",
            "url": "https://cwe.mitre.org/data/definitions/347",
        }
    ]
    assert detail["impact"][0]["id"] == "CAPEC-115"
    assert detail["timeline"][0] == {"date": "2026-05-28", "text": "Updated fix release timeline."}
    assert "Upgrade to a fixed PAN-OS release." in detail["solution"]
    assert "https://security.paloaltonetworks.com/json/CVE-2026-0265" in detail["reference_links"]


def test_parse_paloalto_detail_extracts_multi_cve_rollup() -> None:
    html = (FIXTURES / "detail_multi_cve.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["advisory_id"] == "PAN-SA-2026-0007"
    assert detail["severity"] == "MEDIUM"
    assert detail["urgency"] == "MODERATE"
    assert detail["products"] == ["Prisma Browser"]
    assert detail["cve_ids"] == ["CVE-2026-4439", "CVE-2026-4440"]
    assert detail["product_status"] == [
        {
            "version": "Prisma Browser",
            "affected": "< 146.10.7.154",
            "unaffected": ">= 148.6.3.96",
        }
    ]
