import json
from pathlib import Path

from vuln_scraper.scrapers.github_advisory.parsers.detail import parse_advisory_response
from vuln_scraper.scrapers.github_advisory.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_github_advisory_list_maps_records() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_advisory_list(payload, page=1)

    assert page.page == 1
    assert page.total_pages is None
    assert len(page.entries) == 2

    first = page.entries[0]
    assert first.key == "github_advisory:abcd-1234-efgh"
    assert first.display_id == "GHSA-abcd-1234-efgh"
    assert first.title == "Heartbleed security advisory"
    assert first.vuln_type == "reviewed"
    assert first.disclosure_date == "2026-06-01T02:30:56Z"
    assert first.status == "high"
    assert first.embedded_detail["ghsa_id"] == "GHSA-abcd-1234-efgh"
    assert first.embedded_detail["cve_ids"] == ["CVE-2050-00000"]
    assert first.embedded_detail["vulnerabilities"][0]["package"] == {
        "ecosystem": "npm",
        "name": "a-package",
    }

    record = first.to_record(first.embedded_detail)
    assert record["type"] == "github_advisory"
    assert record["code"] == "abcd-1234-efgh"
    assert record["cve_code"] == "2050-00000"
    assert record["details"]["github_advisory"]["severity"] == "high"


def test_parse_github_advisory_list_accepts_ghsa_without_cve() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    entry = parse_advisory_list(payload, page=1).entries[1]
    record = entry.to_record(entry.embedded_detail)

    assert entry.key == "github_advisory:wxyz-5678-ijkl"
    assert record["cve_code"] is None
    assert entry.embedded_detail["vulnerabilities"][0]["package"]["ecosystem"] == "pip"


def test_parse_github_advisory_detail_preserves_raw_payload() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_advisory_response(payload).to_dict()

    assert detail["ghsa_id"] == "GHSA-abcd-1234-efgh"
    assert detail["cve_id"] == "CVE-2050-00000"
    assert detail["advisory_type"] == "reviewed"
    assert detail["severity"] == "high"
    assert detail["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2050-00000"]
    assert detail["cwes"] == [{"cwe_id": "CWE-400", "name": "Uncontrolled Resource Consumption"}]
    assert detail["raw"]["ghsa_id"] == "GHSA-abcd-1234-efgh"
