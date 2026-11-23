from __future__ import annotations

from xml.etree import ElementTree

from vuln_scraper.client import FetchError
from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.timestamps import LOCAL_TIMEZONE

from .detail import parse_rss_item


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str) -> ListPage:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise FetchError("Invalid BleepingComputer RSS feed") from exc
    channel = root.find("channel")
    if root.tag != "rss" or channel is None:
        raise FetchError("Missing channel in BleepingComputer RSS feed")

    items = channel.findall("item")
    entries: dict[str, ListEntry] = {}
    for item in items:
        try:
            detail = parse_rss_item(item)
        except (ValueError, OverflowError):
            continue
        if detail.code in entries:
            continue
        entries[detail.code] = ListEntry(
            identity=VulnerabilityId(provider.upper(), detail.code),
            title=detail.title,
            vuln_type=None,
            disclosure_date=detail.published_at.astimezone(LOCAL_TIMEZONE).date().isoformat(),
            status=None,
            provider=provider,
            source_url=source_url,
            embedded_detail=detail.to_dict(),
        )

    if items and not entries:
        raise FetchError("No usable items in BleepingComputer RSS feed")
    return ListPage(page, list(entries.values()), total_pages=1, total_records=len(entries), exhausted=not entries)
