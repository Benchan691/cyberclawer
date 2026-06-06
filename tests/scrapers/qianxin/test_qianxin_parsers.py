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
    assert tuple(detail["description"]) == (
        "security_advisory",
        "vulnerability_information",
        "threat_assessment",
        "affected_assets",
        "recommendations",
        "references",
    )
    assert detail["description"]["security_advisory"].endswith("已公开。")
    vulnerability = detail["description"]["vulnerability_information"]
    assert vulnerability["published_date"] == "2026-06-03"
    assert vulnerability["affected_versions"] == ["Redis < 7.0", "Redis < 8.0"]
    assert vulnerability["risk"] == {"qianxin_cert_rating": "高危", "risk_level": "红色"}
    assert vulnerability["current_threat_status"]["poc_status"] == "已公开"
    assessment = detail["description"]["threat_assessment"]
    assert assessment["cvss_3_1_score"] == "8.8"
    assert assessment["cvss_vector"]["attack_vector"] == "网络"
    assert assessment["exploitation_conditions"] == ["目标运行受影响版本。", "攻击者可访问服务。"]
    assert detail["description"]["affected_assets"] == "全球存在受影响资产。"
    assert detail["description"]["recommendations"] == ["升级至安全版本。", "限制服务访问。"]
    assert detail["description"]["references"] == [
        "1.[相关链接] https://redis.io/security"
    ]
    assert "奇安信 CERT" not in json.dumps(detail["description"], ensure_ascii=False)
    assert "raw_sections" not in detail
    assert detail["prev_article"] == {"id": "1864", "title": "Previous advisory"}
    assert "content" not in detail["raw"]


def test_parse_qianxin_detail_keeps_exact_six_chapter_defaults_when_sections_are_missing() -> None:
    detail = parse_article_detail(
        {"id": 1, "content": "<div><h1>第一章 安全通告</h1><p>Only chapter one.</p></div>"}
    ).to_dict()

    assert detail["description"] == {
        "security_advisory": "Only chapter one.",
        "vulnerability_information": {},
        "threat_assessment": {},
        "affected_assets": "",
        "recommendations": [],
        "references": [],
    }


def test_parse_qianxin_detail_routes_chapters_by_title_when_chapter_four_is_omitted() -> None:
    content = """<div id="poc-preview"><div>
<h1>第一章 安全通告</h1><p>Advisory text.</p>
<h1>第二章 漏洞信息</h1><p>Summary.</p>
<h1>第三章 威胁评估</h1><p>Assessment.</p>
<h1>第四章 处置建议</h1><p>修复解决方案 patch info.</p><p>临时缓解方案.</p>
<h1>第五章 参考资料</h1><p>1.[相关链接] https://example.test/ref</p>
<p>奇安信 CERT</p>
</div></div>"""

    detail = parse_article_detail({"id": 1861, "content": content}).to_dict()["description"]

    assert detail["affected_assets"] == ""
    assert detail["recommendations"] == ["修复解决方案 patch info.", "临时缓解方案."]
    assert detail["references"] == ["1.[相关链接] https://example.test/ref"]


def test_parse_qianxin_detail_falls_back_to_numeric_mapping_for_unlabeled_chapter_headings() -> None:
    content = """<div id="poc-preview"><div>
<h1>第一章 安全通告</h1><p>Advisory.</p>
<h1>第二章</h1><p>Vulnerability summary.</p>
<h1>第三章</h1><p>Threat context.</p>
<h1>第四章</h1><p>Asset exposure summary.</p>
<h1>第五章</h1><p>Upgrade immediately.</p>
<h1>第六章</h1><p>1.[相关链接] https://example.test/detail</p>
</div></div>"""

    detail = parse_article_detail({"id": 2, "content": content}).to_dict()["description"]

    assert detail["security_advisory"] == "Advisory."
    assert detail["vulnerability_information"]["summary"] == "Vulnerability summary."
    assert detail["threat_assessment"]["context"] == "Threat context."
    assert detail["affected_assets"] == "Asset exposure summary."
    assert detail["recommendations"] == ["Upgrade immediately."]
    assert detail["references"] == ["1.[相关链接] https://example.test/detail"]
