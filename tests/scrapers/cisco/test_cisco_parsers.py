import json
from pathlib import Path

from vuln_scraper.scrapers.cisco.parsers.detail import parse_detail_response
from vuln_scraper.scrapers.cisco.parsers.list import parse_advisories_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cisco_list_embeds_detail_and_paging() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_advisories_list(payload, page=1)

    assert page.total_records == 2
    assert len(page.entries) == 2

    first = page.entries[0]
    assert first.key == "cisco:cisco-sa-foo-123"
    assert first.display_id == "CISCO-cisco-sa-foo-123"
    assert first.title == "Cisco Product Remote Code Execution Vulnerability"
    assert first.vuln_type == "Critical"
    assert first.disclosure_date == "2026-05-20T15:00:00"

    first_record = first.to_record(detail_url="https://apix.cisco.com/security/advisories/v2/advisory/cisco-sa-foo-123")
    assert first_record["type"] == "cisco"
    assert first_record["code"] == "cisco-sa-foo-123"
    assert first_record["cve_code"] == "2026-12345"
    assert first_record["details"]["cisco"]["cve_ids"] == ["CVE-2026-12345"]
    assert first_record["details"]["cisco"]["bug_ids"] == ["CSCwa12345", "CSCwa99999"]

    second = page.entries[1]
    second_record = second.to_record(detail_url="https://example.invalid")
    assert second_record["cve_code"] is None
    assert second_record["details"]["cisco"]["cve_ids"] == ["CVE-2026-10001", "CVE-2026-10002"]


def test_parse_cisco_detail_response_extracts_fields() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_detail_response(payload).to_dict()

    assert detail["advisory_id"] == "cisco-sa-foo-123"
    assert detail["sir"] == "Critical"
    assert detail["status"] == "Final"
    assert detail["first_published"] == "2026-05-20T15:00:00"
    assert detail["cve_ids"] == ["CVE-2026-12345"]
    assert detail["bug_ids"] == ["CSCwa12345", "CSCwa99999"]
    assert detail["product_names"] == ["Cisco IOS XE Software", "Cisco Catalyst 9000"]
    assert detail["publication_url"].endswith("cisco-sa-foo-123")
