from datetime import UTC, datetime
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from vuln_scraper.mongo import build_mongo_document
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers.wiz.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.wiz.parsers.list import parse_rss_list
from vuln_scraper.scrapers.wiz.provider import WizProvider


FIXTURES = Path(__file__).parent / "fixtures"


def test_rss_preserves_guid_identity_dates_and_content_without_a_feed_limit():
    xml = (FIXTURES / "list.xml").read_text()
    page = parse_rss_list(xml, page=1)

    assert page.total_pages == 1
    assert page.total_records == 2
    assert not page.exhausted
    first, second = page.entries
    assert first.key == "wiz:408d8c76-b6ae-80b2-8035-d638c24854dc"
    assert first.title == "Example Cloud Campaign"
    assert first.vuln_type == "Campaign"
    assert first.disclosure_date == "2026-10-21"
    assert first.status is None
    assert first.embedded_detail["published_at"] == "2026-10-21T00:00:00+00:00"
    assert first.embedded_detail["summary"] == "Attackers exploited CVE-2026-12345..."
    assert first.embedded_detail["cve_ids"] == ["CVE-2026-12345"]
    assert second.vuln_type == "Research"
    assert second.disclosure_date == "2020-09-01"

    renamed = xml.replace("example-cloud-campaign", "renamed-cloud-campaign")
    assert parse_rss_list(renamed, page=1).entries[0].key == first.key


def test_rss_does_not_truncate_the_feed_to_fifty_entries():
    items = "".join(
        f"<item><title>Incident {number}</title>"
        f"<guid>00000000-0000-0000-0000-{number:012x}</guid>"
        f"<link>https://threats.wiz.io/all-incidents/incident-{number}</link></item>"
        for number in range(1, 61)
    )
    assert len(parse_rss_list(f"<rss><channel>{items}</channel></rss>", page=1).entries) == 60


@pytest.mark.parametrize("xml", [
    "<html>Not a feed</html>", "<rss>", "<rss/>",
    "<rss><channel><item><title>Unparseable item</title></item></channel></rss>",
])
def test_invalid_feed_is_reported_as_a_failure(xml):
    with pytest.raises(ValueError, match="Wiz"):
        parse_rss_list(xml, page=1)


def test_verified_empty_feed_and_missing_publication_dates():
    assert parse_rss_list("<rss><channel/></rss>", page=1).exhausted
    xml = (FIXTURES / "list.xml").read_text().replace("Wed, 21 Oct 2026 00:00:00 GMT", "not a date")
    first = parse_rss_list(xml, page=1).entries[0]
    assert first.disclosure_date is None
    assert first.embedded_detail["published_at"] is None


def test_detail_extracts_full_content_properties_cves_and_references():
    detail = parse_detail_page((FIXTURES / "detail.html").read_text()).to_dict()

    assert detail["title"] == "Example Cloud Campaign"
    assert "complete second paragraph" in detail["content"]
    assert "Navigation must not" not in detail["content"]
    assert "Footer must not" not in detail["content"]
    assert "Last edited" not in detail["content"]
    assert detail["published_at"] == "2026-10-21T00:00:00+00:00"
    assert detail["updated_at"] == "2026-10-29T09:31:00+00:00"
    assert detail["actors"] == ["Example Actor", "Second Actor"]
    assert detail["threat_type"] == "Campaign"
    assert detail["initial_access"] == ["Exploitation of public-facing application"]
    assert detail["impact"] == ["Data exfiltration"]
    assert detail["observed_techniques"] == ["Credential Access"]
    assert detail["targeted_technologies"] == ["Example Cloud"]
    assert detail["source_status"] == "Finalized"
    assert detail["cve_ids"] == ["CVE-2026-12345", "CVE-2026-54321"]
    assert "https://www.wiz.io/blog/example-cloud-campaign" in detail["reference_links"]
    assert detail["reference_links"].count("https://threats.wiz.io/all-techniques/credential-access") == 1


@pytest.mark.parametrize("html", [
    "<html><h1>Access denied</h1></html>",
    '<h1 class="notion-header__title">Incident</h1><article class="notion-root"></article>',
])
def test_missing_article_content_does_not_become_a_successful_detail(html):
    with pytest.raises(ValueError, match="Wiz detail page"):
        parse_detail_page(html)


def test_historical_incidents_with_only_properties_preserve_all_available_content():
    soup = BeautifulSoup((FIXTURES / "detail.html").read_text(), "lxml")
    for paragraph in soup.select("article > p"):
        paragraph.decompose()
    detail = parse_detail_page(str(soup)).to_dict()

    assert detail["summary"] in detail["content"]
    assert "Example Actor" in detail["content"]
    assert detail["targeted_technologies"] == ["Example Cloud"]


def test_wiz_documents_use_shared_schema_and_source_publication_dates():
    provider = WizProvider()
    entry = provider.parse_list((FIXTURES / "list.xml").read_text(), page=1).entries[0]
    url = provider.detail_url(entry.display_id)
    detail = provider.finalize_detail(
        provider.parse_detail((FIXTURES / "detail.html").read_text()).to_dict(),
        entry=entry, detail_url=url,
    )
    document = build_mongo_document(entry.to_record(detail, detail_url=url),
                                    {"scraped_at": "2026-11-18T03:00:00Z"})

    validate_v2_document(document, "news")
    assert document["_id"] == entry.key
    assert document["source"]["provider"] == "wiz"
    assert document["source"]["detail_url"] == url
    assert document["published_at"] == datetime(2026, 10, 21, tzinfo=UTC)
    assert document["updated_at"] == datetime(2026, 10, 29, 9, 31, tzinfo=UTC)
    assert document["cve_ids"] == ["CVE-2026-12345", "CVE-2026-54321"]
    assert "severity" not in document
    assert "feed_guid" not in document["details"]
    assert "complete second paragraph" in document["details"]["content"]
