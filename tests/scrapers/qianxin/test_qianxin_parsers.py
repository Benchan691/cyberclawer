import json
from pathlib import Path

from vuln_scraper.scrapers.qianxin.parsers.detail import parse_article_detail
from vuln_scraper.scrapers.qianxin.parsers.list import parse_article_notice_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_qianxin_list_maps_records_and_pagination() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_article_notice_list(payload, page=1)

    assert page.total_records == 12
    assert page.total_pages == 2
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "qianxin:1868"
    assert first.display_id == "QIANXIN-1868"
    assert first.title == "Redis Lua 脚本远程代码执行漏洞(CVE-2026-23631)安全风险通告"
    assert first.vuln_type == "风险通告"
    assert first.status == "High"
    assert first.disclosure_date == "2026-06-03"
    assert first.embedded_detail["threat_status"] == "已复现"
    assert first.embedded_detail["cve_ids"] == ["CVE-2026-23631"]
    assert first.embedded_detail["vuln_ids"] == ["459093"]
    assert first.to_record(first.embedded_detail)["cve_code"] == "2026-23631"


def test_parse_qianxin_detail_extracts_article_content_links_and_cves() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_article_detail(payload).to_dict()

    assert detail["article_id"] == "1868"
    assert detail["title"] == "Redis Lua 脚本远程代码执行漏洞(CVE-2026-23631)安全风险通告"
    assert detail["threat_status"] == "已复现"
    assert detail["category"] == "风险通告"
    assert detail["published_date"] == "2026-06-03"
    assert detail["updated_date"] == "2026-06-03"
    assert detail["cve_ids"] == ["CVE-2026-23631"]
    assert detail["reference_links"] == ["https://redis.io/security"]
    assert "第一章_安全通告" in detail["raw_sections"]
    assert detail["prev_article"] == {"id": "1864", "title": "Previous advisory"}
    assert "content" not in detail["raw"]
