import json
from pathlib import Path

from vuln_scraper.scrapers.cve.parsers.detail import parse_cve_detail_response
from vuln_scraper.scrapers.cve.parsers.list import parse_cve_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cve_list_embeds_nvd_detail() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_cve_list(payload, page=1)

    assert page.total_pages == 1
    assert page.total_records == 1
    assert page.start_index == 0
    assert page.results_per_page == 1
    assert len(page.entries) == 1

    entry = page.entries[0]
    assert entry.key == "cve:2024-3094"
    assert entry.display_id == "CVE-2024-3094"
    assert entry.title == "Malicious code was discovered in the upstream tarballs of xz."
    assert entry.disclosure_date == "2024-03-29T17:15:21.150"

    record = entry.to_record(detail_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094")

    assert record["type"] == "cve"
    assert record["code"] == "2024-3094"
    assert record["cve_code"] is None
    assert record["details"]["cve"]["cve_id"] == "CVE-2024-3094"
    assert record["details"]["cve"]["metrics"]["cvss_v31"][0]["cvssData"]["baseSeverity"] == "CRITICAL"
    assert record["details"]["cve"]["raw"]["id"] == "CVE-2024-3094"


def test_parse_cve_detail_response_accepts_full_nvd_payload() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    detail = parse_cve_detail_response(payload).to_dict()

    assert detail["cve_id"] == "CVE-2024-3094"
    assert detail["published"] == "2024-03-29T17:15:21.150"
    assert detail["last_modified"] == "2025-08-19T01:15:57.407"
    assert detail["references"][0]["url"].endswith("CVE-2024-3094")
