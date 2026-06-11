import json
from pathlib import Path

from vuln_scraper.scrapers.cnnvd.parsers.detail import parse_vulnerability_detail
from vuln_scraper.scrapers.cnnvd.parsers.list import parse_vulnerability_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cnnvd_list_maps_records_and_pagination() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_vulnerability_list(payload, page=1)

    assert page.total_records == 12
    assert page.total_pages == 2
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "cnnvd:202606-1911"
    assert first.display_id == "CNNVD-202606-1911"
    assert first.title == "Google Chrome 安全漏洞"
    assert first.vuln_type == "其他"
    assert first.status == "高危"
    assert first.disclosure_date == "2026-06-08"
    assert first.embedded_detail["id"] == "record-1911"
    assert first.embedded_detail["cnnvdCode"] == "CNNVD-202606-1911"
    assert first.embedded_detail["hazardLevel"] == 2
    assert first.to_record(first.embedded_detail)["cve_code"] == "2026-11628"


def test_parse_cnnvd_detail_returns_raw_inner_object() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_vulnerability_detail(payload).to_dict()

    assert detail == payload["data"]["cnnvdDetail"]
    assert detail["id"] == "record-1911"
    assert detail["vulName"] == "Google Chrome 安全漏洞"
    assert detail["cnnvdCode"] == "CNNVD-202606-1911"
    assert detail["hazardLevel"] == 2


def test_parse_cnnvd_received_detail_variant() -> None:
    payload = {
        "data": {
            "cnnvdDetail": None,
            "receviceVulDetail": {
                "id": "received-1",
                "cnnvdCode": "CNNVD-202606-2000",
                "vulName": "Received vulnerability",
                "cveCode": "2026-12000",
            },
        }
    }

    detail = parse_vulnerability_detail(payload).to_dict()

    assert detail == payload["data"]["receviceVulDetail"]
