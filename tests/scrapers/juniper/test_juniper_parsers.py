from pathlib import Path

from vuln_scraper.scrapers.juniper.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.juniper.parsers.list import parse_advisory_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_juniper_list_extracts_coveo_results() -> None:
    page = parse_advisory_list((FIXTURES / "list.html").read_text(encoding="utf-8"), page=1)

    assert page.total_records == 2
    assert page.total_pages == 1
    assert len(page.entries) == 2
    first = page.entries[0]
    assert first.key == "juniper:JSA93456"
    assert first.display_id == "JUNIPER-JSA93456"
    assert first.title == "Junos OS: Multiple vulnerabilities resolved in J-Web"
    assert first.vuln_type == "Security Advisories"
    assert first.status == "Security Advisories"
    assert first.disclosure_date == "2026-05-29"
    assert first.embedded_detail["source_name"] == "Knowledge"


def test_parse_juniper_live_quantic_search_results() -> None:
    html = """
    <main>
      <div>Results 1-10 of 1,365 in 1.28 seconds</div>
      <c-quantic-result>
        <c-quantic-result-template>
          <div class="lgc-bg slds-p-vertical_medium">
            <span>Knowledge</span>
            <a href="/s/article/2026-05-Reference-Advisory-Status-of-Copy-Fail-vulnerability-on-Juniper-Products-CVE-2026-31431">
              JSA108949 : 2026-05 Reference Advisory: Status of Copy Fail vulnerability on Juniper Products (CVE-2026-31431)
            </a>
            <span>Security Advisories</span>
            <span>2026-06-01</span>
            <p>Article ID:JSA108949 CVSS Score:CVSS: v3.1: 7.8</p>
          </div>
        </c-quantic-result-template>
      </c-quantic-result>
    </main>
    """

    page = parse_advisory_list(html, page=1)

    assert page.total_records == 1365
    assert page.total_pages == 137
    assert len(page.entries) == 1
    first = page.entries[0]
    assert first.key == "juniper:JSA108949"
    assert first.title == (
        "2026-05 Reference Advisory: Status of Copy Fail vulnerability on Juniper Products "
        "(CVE-2026-31431)"
    )
    assert first.disclosure_date == "2026-06-01"
    assert first.embedded_detail["reference_links"] == [
        "https://supportportal.juniper.net/s/article/2026-05-Reference-Advisory-Status-of-Copy-Fail-vulnerability-on-Juniper-Products-CVE-2026-31431"
    ]


def test_parse_juniper_detail_extracts_article_fields() -> None:
    detail = parse_detail_page((FIXTURES / "detail.html").read_text(encoding="utf-8")).to_dict()

    assert detail["article_id"] == "JSA93456"
    assert detail["article_type"] == "Security Advisories"
    assert detail["source_name"] == "Knowledge"
    assert detail["published_date"] == "2026-05-29"
    assert detail["updated_date"] == "2026-05-30"
    assert detail["cve_ids"] == ["CVE-2026-55555", "CVE-2026-55556"]
    assert detail["products"] == ["Junos OS 24.2"]
    assert "fixed Junos OS" in detail["solution"]
    assert detail["workaround"] == "Disable J-Web until fixed."
