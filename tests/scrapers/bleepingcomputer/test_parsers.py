from pathlib import Path
from xml.etree import ElementTree

import pytest

from vuln_scraper.client import FetchError
from vuln_scraper.scrapers.bleepingcomputer.provider import BleepingComputerProvider


FEED = Path(__file__).parent / "fixtures" / "feed.xml"


def test_rss_items_are_complete_inline_records():
    provider = BleepingComputerProvider()
    parsed = provider.parse_list(FEED.read_text(encoding="utf-8"), page=1)
    assert parsed.total_pages == 1
    assert parsed.total_records == 3
    assert [entry.identity.code for entry in parsed.entries] == [
        "security/example-vendor-patches",
        "microsoft/example-release",
        "hardware/example-older-post",
    ]
    first, second, third = parsed.entries
    assert first.title == "Example vendor patches CVE-2026-12345"
    assert first.disclosure_date == second.disclosure_date == "2026-11-13"
    assert third.disclosure_date == "2026-11-12"
    assert first.embedded_detail == {
        "published_at": "2026-11-13T01:15:00+00:00",
        "summary": "The update addresses cve-2026-12345 and CVE-2026-23456.",
        "author": "Test Reporter",
        "categories": ["Security", "Software"],
        "cve_ids": ["CVE-2026-12345", "CVE-2026-23456"],
    }
    assert second.embedded_detail["categories"] == ["Microsoft"]
    assert third.embedded_detail["summary"] is None


def test_detail_parser_accepts_a_single_rss_item():
    item = ElementTree.parse(FEED).find("channel/item")
    detail = BleepingComputerProvider().parse_detail(ElementTree.tostring(item, encoding="unicode"))
    assert detail.code == "security/example-vendor-patches"
    assert detail.author == "Test Reporter"


@pytest.mark.parametrize("xml", ["<rss>", "<html/>", "<rss><channel><item/></channel></rss>"])
def test_invalid_feed_raises_fetch_error(xml):
    with pytest.raises(FetchError, match="BleepingComputer RSS feed"):
        BleepingComputerProvider().parse_list(xml, page=1)


def test_empty_channel_is_exhausted():
    parsed = BleepingComputerProvider().parse_list("<rss><channel/></rss>", page=1)
    assert parsed.exhausted
    assert parsed.total_records == 0
