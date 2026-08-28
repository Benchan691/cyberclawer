from pathlib import Path

from vuln_scraper.scrapers.hpe.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.hpe.parsers.list import parse_rss_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_hpe_rss_handles_namespaces_duplicates_and_malformed_items() -> None:
    xml = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_rss_list(xml, page=1)

    assert page.total_pages == 1
    assert page.total_records == 2
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "hpe:hpesbnw05119en_us"
    assert first.title.startswith("HPESBNW05119 rev.1")
    assert first.disclosure_date == "2026-08-07"
    assert first.status == "Critical"
    assert first.embedded_detail["creator"] == "Hewlett Packard Enterprise"
    assert first.embedded_detail["doc_display_url"] == (
        "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05119en_us&docLocale=en_US"
    )
    assert page.entries[1].identity.code == "hpesbnw05125en_us"


def test_parse_hpe_detail_extracts_metadata_sections_cves_links_and_tables() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["bulletin_id"] == "HPESBNW05119"
    assert detail["doc_id"] == "hpesbnw05119en_us"
    assert detail["document_subtype"] == "Security Bulletin"
    assert detail["last_updated"] == "2026-08-07"
    assert detail["release_date"] == "2026-08-07"
    assert detail["document_version"] == "1"
    assert detail["severity"] == "Critical"
    assert detail["summary"] == "HPE has released a patch for two security vulnerabilities."
    assert detail["affected_products"] == "HPE Private 5G Core 1.26.1.2 and below"
    assert detail["supported_versions"] == "HPE Private 5G Core 1.26.1.2 and prior"
    assert "version 1.26.1.3" in detail["resolution"]
    assert detail["history"].startswith("Version:1 (rev.1)")
    assert detail["cve_ids"] == ["CVE-2026-54763", "CVE-2026-33377"]
    assert "CVSS v3.1 Base Score: 10.0" in detail["cvss_text"]
    assert detail["cvss_entries"] == [
        {
            "reference": "CVE-2026-33377",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
            "base_score": "7.1",
        },
        {
            "reference": "CVE-2026-54763",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            "base_score": "10.0",
        },
    ]
    assert len(detail["tables"]) == 1
    assert "https://csaf.example.test/hpe.txt" in detail["reference_links"]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-54763" in detail["reference_links"]
    assert "vulnerability_summary" in detail["raw_sections"]
    assert "supported_software_versions" in detail["raw_sections"]
    assert "CVSS:3.1/AV:N" in detail["raw_sections"]["background"]
