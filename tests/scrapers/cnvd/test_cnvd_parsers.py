from pathlib import Path

from vuln_scraper.scrapers.cnvd.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.cnvd.parsers.list import parse_flaw_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cnvd_list_maps_rows_and_pagination() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_flaw_list(html, page=1)

    assert page.total_records == 45
    assert page.total_pages == 3
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "cnvd:2026-21550"
    assert first.display_id == "CNVD-2026-21550"
    assert first.title == "Example Product 远程代码执行漏洞"
    assert first.status == "高"
    assert first.disclosure_date == "2026-06-01"
    assert first.embedded_detail["click_count"] == 123
    assert first.embedded_detail["comment_count"] == 4
    assert first.embedded_detail["follow_count"] == 5
    assert first.to_record(first.embedded_detail)["cve_code"] is None


def test_parse_cnvd_detail_extracts_labeled_fields_links_and_cves() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["cnvd_id"] == "CNVD-2026-21550"
    assert detail["title"] == "Example Product 远程代码执行漏洞"
    assert detail["severity"].startswith("高")
    assert detail["cvss_score"] == "9.8"
    assert detail["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert detail["affected_products"] == ["Example Product 1.0", "Example Product 2.0"]
    assert detail["cve_ids"] == ["CVE-2026-12345", "CVE-2026-12346"]
    assert detail["description"] == "攻击者可利用该漏洞执行任意代码。"
    assert detail["solution"] == "升级至安全版本。"
    assert detail["published_date"] == "2026-06-01"
    assert "https://example.test/advisory/CNVD-2026-21550" in detail["reference_links"]
