import json
from pathlib import Path

from vuln_scraper.scrapers.cnnvd.parsers.detail import parse_warn_detail
from vuln_scraper.scrapers.cnnvd.parsers.list import parse_warn_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cnnvd_list_maps_records_and_pagination() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_warn_list(payload, page=1)

    assert page.total_records == 3
    assert page.total_pages == 2
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "cnnvd:0f9ea9d7144547dcaf6374acae1c7b97"
    assert first.display_id == "CNNVD-0f9ea9d7144547dcaf6374acae1c7b97"
    assert first.title == "人工智能重要安全漏洞通报-OpenClaw多个安全漏洞"
    assert first.vuln_type == "漏洞通报"
    assert first.status == "漏洞通报"
    assert first.disclosure_date == "2026-05-20"
    assert first.embedded_detail["created_by"] == "zhangdan"
    assert first.embedded_detail["summary"] == "OpenClaw advisory summary"
    assert first.to_record(first.embedded_detail)["cve_code"] is None


def test_parse_cnnvd_detail_extracts_body_links_and_cves() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_warn_detail(payload).to_dict()

    assert detail["warn_id"] == "0f9ea9d7144547dcaf6374acae1c7b97"
    assert detail["title"] == "人工智能重要安全漏洞通报-OpenClaw多个安全漏洞"
    assert detail["published_date"] == "2026-05-20"
    assert detail["created_by"] == "zhangdan"
    assert detail["cve_ids"] == ["CVE-2026-12345", "CVE-2026-12346"]
    assert detail["severity_counts"] == {"超危": 7, "高危": 33, "中危": 27, "低危": 2}
    assert detail["reference_links"] == ["https://github.com/openclaw/openclaw/releases"]
    assert "漏洞介绍" in detail["raw_sections"]
