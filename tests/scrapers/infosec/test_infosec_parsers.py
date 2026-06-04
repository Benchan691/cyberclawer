from pathlib import Path

from vuln_scraper.scrapers.infosec.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.infosec.parsers.list import parse_alerts_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_infosec_list_extracts_alert_rows() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_alerts_list(html, page=1)

    assert page.total_records == 3
    assert len(page.entries) == 3
    first = page.entries[0]
    assert first.key == "infosec:1893"
    assert first.display_id == "INFOSEC-1893"
    assert first.title == "Security Alert (A26-05-48): Multiple Vulnerabilities in Microsoft Edge"
    assert first.vuln_type == "A26-05-48"
    assert first.status == "Security Alert"
    assert first.disclosure_date == "2026-05-29"
    assert first.embedded_detail == {
        "_list_summary": True,
        "alert_code": "A26-05-48",
        "alert_type": "Security Alert",
        "published_date": "2026-05-29",
        "summary": "Microsoft has released security updates to address multiple vulnerabilities in Microsoft Edge.",
        "govcert_detail_url": "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893",
    }

    third = page.entries[2]
    assert third.key == "infosec:1891"
    assert third.status == "High Threat Security Alert"
    assert third.vuln_type == "A26-05-46"


def test_parse_infosec_detail_reuses_govcert_sections() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["alert_code"] == "A26-05-48"
    assert detail["alert_type"] == "Security Alert"
    assert detail["published_date"] == "2026-05-29"
    assert detail["description"].startswith("Microsoft Edge contains multiple vulnerabilities")
    assert detail["affected_systems"] == ["Microsoft Edge", "Chromium-based Edge"]
    assert detail["impact"] == "Remote code execution."
    assert detail["recommendation"] == "Apply the latest security update."
    assert detail["more_information_links"] == [
        "https://example.test/edge-advisory",
        "https://example.test/text-link",
    ]
    assert detail["tags"] == ["Microsoft", "Edge"]
    assert detail["cve_ids"] == ["CVE-2026-10022", "CVE-2026-9872"]
    assert detail["raw_sections"]["more_information"].endswith("https://example.test/text-link")
    assert detail["summary"] is None
    assert detail["govcert_detail_url"] is None


def test_parse_infosec_detail_handles_missing_optional_sections() -> None:
    html = (FIXTURES / "detail_minimal.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["alert_code"] == "A26-05-47"
    assert detail["description"] == "Google released a security update."
    assert detail["affected_systems"] == []
    assert detail["impact"] is None
    assert detail["more_information_links"] == []
