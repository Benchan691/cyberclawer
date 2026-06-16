import json
from pathlib import Path

from vuln_scraper.scrapers.msrc.parsers.detail import expand_cvrf_document, parse_cvrf_document
from vuln_scraper.scrapers.msrc.parsers.list import parse_update_list


FIXTURES = Path(__file__).parent / "fixtures"


def load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_parse_update_list_reads_odata_value() -> None:
    page = parse_update_list(load_json("list.json"), page=1, provider="msrc")

    assert page.total_pages == 1
    assert page.total_records == 2
    assert [entry.key for entry in page.entries] == ["msrc:2026-Jun", "msrc:2026-May"]
    assert page.entries[0].title == "June 2026 Security Updates"
    assert page.entries[0].disclosure_date == "2026-06-17T07:00:00Z"
    assert page.entries[0].embedded_detail["cvrf_url"].endswith("/2026-Jun")


def test_parse_cvrf_document_preserves_raw_monthly_payload() -> None:
    payload = load_json("detail.json")

    detail = parse_cvrf_document(payload).to_dict()

    assert detail["DocumentTitle"]["Value"] == "June 2026 Security Updates"
    assert len(detail["Vulnerability"]) == 2


def test_expand_cvrf_document_creates_one_record_per_cve() -> None:
    page = parse_update_list(load_json("list.json"), page=1, provider="msrc")
    detail = parse_cvrf_document(load_json("detail.json")).to_dict()

    records = expand_cvrf_document(
        page.entries[0],
        detail,
        detail_url="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun",
        provider="msrc",
    )

    assert [record["code"] for record in records] == ["2026-41108", "2026-50001"]
    assert records[0]["type"] == "msrc"
    assert records[0]["cve_code"] == "2026-41108"
    assert records[0]["title"] == "Windows DNS Client Elevation of Privilege Vulnerability"
    assert records[0]["vuln_type"] == "Elevation of Privilege"
    assert records[0]["disclosure_date"] == "2026-06-17T07:00:00"

    msrc = records[0]["details"]["msrc"]
    assert msrc["cve_id"] == "CVE-2026-41108"
    assert msrc["description"] == "Heap-based buffer overflow in Microsoft Windows DNS."
    assert msrc["cwe"] == [{"id": "CWE-122", "value": "Heap-based Buffer Overflow"}]
    assert msrc["product_statuses"][0]["product_names"] == [
        "Windows 10 Version 1809 for 32-bit Systems",
        "Windows 10 Version 1809 for x64-based Systems",
    ]
    assert msrc["threats"][0]["product_names"] == [
        "Windows 10 Version 1809 for 32-bit Systems"
    ]
    assert msrc["remediations"][0]["description"] == "Install the security update."
    assert msrc["acknowledgments"][0]["names"] == ["Researcher One"]
    assert msrc["cvss"][0]["base_score"] == "8.8"
    assert msrc["document_id"] == "2026-Jun"
    assert msrc["document_title"] == "June 2026 Security Updates"
    assert msrc["raw"]["CVE"] == "CVE-2026-41108"


def test_expand_cvrf_document_accepts_missing_optional_containers() -> None:
    page = parse_update_list(load_json("list.json"), page=1, provider="msrc")
    detail = parse_cvrf_document(load_json("detail.json")).to_dict()

    records = expand_cvrf_document(page.entries[0], detail, detail_url=None, provider="msrc")

    msrc = records[1]["details"]["msrc"]
    assert msrc["cve_id"] == "CVE-2026-50001"
    assert msrc["description"] is None
    assert msrc["cwe"] == []
    assert msrc["threats"] == []
    assert msrc["remediations"] == []
    assert msrc["acknowledgments"] == []
