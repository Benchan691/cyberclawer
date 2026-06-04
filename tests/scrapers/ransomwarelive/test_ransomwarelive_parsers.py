import json
from pathlib import Path

from vuln_scraper.scrapers.ransomwarelive.parsers.detail import parse_victim_response
from vuln_scraper.scrapers.ransomwarelive.parsers.list import parse_recent_victims


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_recent_victims_maps_top_level_record_shape() -> None:
    payload = json.loads((FIXTURES / "list.json").read_text(encoding="utf-8"))

    page = parse_recent_victims(payload, page=1)

    assert page.total_pages == 1
    assert page.total_records == 1
    assert len(page.entries) == 1

    entry = page.entries[0]
    assert entry.key == "ransomwarelive:QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw"
    assert entry.display_id == "RANSOMWARELIVE-QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw"
    assert entry.title == "Acme Hospital"
    assert entry.vuln_type == "Healthcare"
    assert entry.disclosure_date == "2026-06-02T10:15:00Z"
    assert entry.status == "lockbit3"

    record = entry.to_record(detail_url="https://api-pro.ransomware.live/victim/QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw")

    assert record["type"] == "ransomwarelive"
    assert record["code"] == "QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw"
    assert record["cve_code"] is None
    assert record["details"]["ransomwarelive"]["victim"] == "Acme Hospital"
    assert record["details"]["ransomwarelive"]["group"] == "lockbit3"
    assert record["details"]["ransomwarelive"]["country"] == "US"
    assert record["details"]["ransomwarelive"]["raw"]["id"] == "QWNtZSBIb3NwaXRhbEBsb2NrYml0Mw"


def test_parse_recent_victims_builds_fallback_id() -> None:
    page = parse_recent_victims(
        [{"victim": "No Id Victim", "group": "akira", "discovered": "2026-06-02"}],
        page=1,
    )

    assert page.entries[0].identity.code == "Tm8gSWQgVmljdGltQGFraXJh"


def test_parse_recent_victims_accepts_nested_data_wrapper() -> None:
    page = parse_recent_victims(
        {
            "data": {
                "victims": [
                    {
                        "victim": "Wrapped Victim",
                        "group": "akira",
                        "discovered": "2026-06-02",
                    }
                ]
            }
        },
        page=1,
    )

    assert len(page.entries) == 1
    assert page.entries[0].title == "Wrapped Victim"


def test_parse_victim_response_accepts_wrapped_detail_payload() -> None:
    payload = json.loads((FIXTURES / "detail.json").read_text(encoding="utf-8"))

    detail = parse_victim_response(payload).to_dict()

    assert detail["victim"] == "Acme Hospital"
    assert detail["group"] == "lockbit3"
    assert detail["infostealer"] == {"employees": 4}
    assert detail["raw"]["website"] == "acme.example"
