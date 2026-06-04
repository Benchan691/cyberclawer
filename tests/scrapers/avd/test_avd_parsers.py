from pathlib import Path

from vuln_scraper.scrapers.avd.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.avd.parsers.list import parse_high_risk_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_avd_list_maps_rows_and_pagination() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_high_risk_list(html, page=1, provider="avd", source_url="https://avd.aliyun.com/high-risk/list")

    assert page.total_pages == 2
    assert page.total_records == 4
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "avd:2026-10001"
    assert first.display_id == "AVD-2026-10001"
    assert first.title == "Product RCE (CVE-2026-10001)"
    assert first.vuln_type == "CWE-78"
    assert first.disclosure_date == "2026-01-01"
    assert first.status == "CVE PoC"
    assert first.embedded_detail["_list_summary"] is True
    assert first.embedded_detail["reference_links"] == [
        "https://avd.aliyun.com/detail?id=AVD-2026-10001"
    ]


def test_parse_avd_detail_extracts_title_cve_and_danger_level() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["cve_id"] == "CVE-2026-10001"
    assert detail["danger_level"] == "高危"
    assert detail["description"] == "description AVD-2026-10001"
