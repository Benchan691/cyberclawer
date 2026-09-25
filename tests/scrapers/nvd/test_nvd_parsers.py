import json
from pathlib import Path

from vuln_scraper.scrapers.nvd.parsers.detail import parse_cve_record
from vuln_scraper.scrapers.nvd.parsers.list import parse_advisory_list

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_advisory_list_from_live_fixture() -> None:
    payload = json.loads((FIXTURES / "cve_response.json").read_text(encoding="utf-8"))
    page = parse_advisory_list(payload, page=1)

    assert page.total_records == payload["totalResults"]
    assert len(page.entries) == len(payload["vulnerabilities"])

    entry = page.entries[0]
    assert entry.identity.type == "NVD"
    assert entry.identity.code.startswith("CVE-")
    assert entry.provider == "nvd"
    # Details are embedded: the runner must not fetch detail pages.
    assert entry.embedded_detail["cve_id"] == entry.identity.code
    assert entry.embedded_detail["detail_url"] == f"https://nvd.nist.gov/vuln/detail/{entry.identity.code}"
    assert entry.disclosure_date == entry.embedded_detail["published_date"]


def test_parse_cve_record_extracts_metrics_and_cwes() -> None:
    payload = json.loads((FIXTURES / "cve_response.json").read_text(encoding="utf-8"))
    cve = next(
        item["cve"]
        for item in payload["vulnerabilities"]
        if item["cve"].get("metrics")
    )

    record = parse_cve_record(cve).to_dict()

    assert record["cve_id"] == cve["id"]
    assert record["description"]
    assert record["title"] == record["description"]
    assert record["published_date"] == cve["published"].split("T", 1)[0]
    assert record["last_modified"] == cve["lastModified"].split("T", 1)[0]
    assert record["vuln_status"] == cve["vulnStatus"]
    if record["severity"]:
        assert record["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    if record["base_score"] is not None:
        assert 0.0 <= record["base_score"] <= 10.0
        assert record["cvss_vector"]
        assert record["cvss"]["vector_string"] == record["cvss_vector"]
        assert record["cvss"]["base_score"] == record["base_score"]
    assert isinstance(record["reference_links"], list)
    assert all(link.startswith(("http", "ftp")) for link in record["reference_links"])
    assert isinstance(record["affected_products"], list)


def test_parse_list_deduplicates_entries() -> None:
    payload = json.loads((FIXTURES / "cve_response.json").read_text(encoding="utf-8"))
    first = payload["vulnerabilities"][0]
    payload["vulnerabilities"] = [first, first]

    page = parse_advisory_list(payload, page=1)
    assert len(page.entries) == 1
