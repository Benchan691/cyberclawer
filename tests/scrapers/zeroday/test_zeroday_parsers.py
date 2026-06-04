from pathlib import Path

from vuln_scraper.scrapers.zeroday.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.zeroday.parsers.list import parse_database_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_database_list_extracts_identity_summary_and_metadata() -> None:
    html = (FIXTURES / "list.html").read_text(encoding="utf-8")

    page = parse_database_list(
        html,
        page=1,
        provider="zeroday",
        source_url="https://www.zero-day.cz/database/",
    )

    assert page.total_pages == 1
    assert page.total_records == 44
    assert len(page.entries) == 2

    entry = page.entries[0]
    assert entry.identity.type == "ZERODAY"
    assert entry.identity.code == "1106"
    assert entry.title == "Multiple vulnerabilities in Google Android"
    assert entry.vuln_type == "Improper input validation"
    assert entry.disclosure_date == "2026-06-01"
    assert entry.status == "patched"
    assert entry.embedded_detail == {
        "_list_summary": True,
        "cve_id": "CVE-2025-48595",
        "weakness": "Improper input validation",
        "summary": (
            "Improper input validation\n"
            "The vulnerability allows a local application to escalate privileges on the device.\n"
            "Note, the vulnerability is being actively exploited in the wild."
        ),
        "software": "Google Android",
        "disclosed_date": "2026-06-01",
        "patched_date": "2026-06-01",
        "patch_status": "patched",
        "reference_links": ["https://source.android.com/docs/security/bulletin/2026/2026-06-01"],
    }

    second = page.entries[1]
    assert second.identity.code == "1095"
    assert second.title == "Backdoor in DAEMON Tools software"
    assert second.status == "unpatched"
    assert second.embedded_detail["cve_id"] is None
    assert second.embedded_detail["software"] == "DAEMON Tools software"


def test_parse_detail_page_extracts_zero_day_fields() -> None:
    html = (FIXTURES / "detail.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["cve_id"] == "CVE-2026-34926"
    assert detail["advisory"] == {
        "title": "SB2026052201 - Multiple vulnerabilities in Trend Micro Apex One",
        "url": "https://www.cybersecurity-help.cz/vdb/SB2026052201",
    }
    assert detail["vulnerable_component"] == "Apex One"
    assert detail["cvss_v3_vector"] == "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C"
    assert detail["cwe"] == {"id": "CWE-23", "name": "Relative Path Traversal"}
    assert detail["description"] == (
        "The vulnerability allows a local privileged user to inject malicious code for deployment to agents.\n"
        "The vulnerability exists due to path traversal in the Apex One server."
    )
    assert detail["disclosed_date"] == "2026-05-21"
    assert detail["patched_date"] == "2026-05-21"
    assert detail["patch_status"] == "patched"
    assert detail["reference_links"] == ["https://success.trendmicro.com/en-US/solution/KA-0023430"]
    assert detail["weakness"] == "Relative Path Traversal"
