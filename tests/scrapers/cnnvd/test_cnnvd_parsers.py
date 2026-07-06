import json
from pathlib import Path

import pytest

from vuln_scraper.client import CaptchaRequiredError
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
    assert first.embedded_detail["cnnvdId"] == "CNNVD-202606-1911"
    assert first.embedded_detail["cveId"] == "CVE-2026-11628"
    assert first.embedded_detail["vulLevel"] == "High"
    assert first.embedded_detail["updateTime"] == "2026-06-09"
    assert first.to_record(first.embedded_detail)["cve_code"] == "2026-11628"


def test_parse_cnnvd_detail_returns_raw_inner_object() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_vulnerability_detail(payload).to_dict()

    assert detail == payload["data"]
    assert detail["id"] == "record-1911"
    assert detail["vulName"] == "Google Chrome 安全漏洞"
    assert detail["cnnvdId"] == "CNNVD-202606-1911"
    assert detail["vulLevel"] == "High"


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


def test_parse_cnnvd_list_strips_search_mark_tags() -> None:
    page = parse_vulnerability_list(
        {
            "data": {
                "total": 1,
                "records": [
                    {
                        "id": "99153750",
                        "vulName": "Wikimedia MediaWiki 跨站脚本漏洞",
                        "cnnvdId": "<mark>CNNVD</mark>-<mark>2026</mark>-<mark>62853948</mark>",
                        "cveId": "CVE-<mark>2026</mark>-58032",
                        "publishDate": "2026-07-01",
                    }
                ],
            }
        },
        page=1,
    )

    entry = page.entries[0]
    assert entry.display_id == "CNNVD-2026-62853948"
    assert entry.to_record(entry.embedded_detail)["cve_code"] == "2026-58032"


def test_parse_cnnvd_detail_accepts_direct_data_with_id() -> None:
    payload = {
        "code": 200,
        "data": {
            "id": "99153750",
            "productId": "170945",
            "cnnvdId": "CNNVD-2026-62853948",
            "cveId": "CVE-2026-58032",
        },
    }

    assert parse_vulnerability_detail(payload).to_dict() == payload["data"]


def test_parse_cnnvd_detail_reports_captcha_required() -> None:
    with pytest.raises(CaptchaRequiredError, match="需要人机验证"):
        parse_vulnerability_detail({"code": 4010, "success": False, "message": "需要人机验证"})


def test_parse_cnnvd_list_reports_captcha_required() -> None:
    with pytest.raises(CaptchaRequiredError, match="需要人机验证"):
        parse_vulnerability_list({"code": 4010, "success": False, "message": "需要人机验证"}, page=1)
