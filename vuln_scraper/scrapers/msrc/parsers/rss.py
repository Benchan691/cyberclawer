from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.rss import parse_rss
from vuln_scraper.scrapers.msrc.config import SOURCE_URL


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str = SOURCE_URL) -> ListPage:
    items = parse_rss(xml, source="MSRC")
    selected = {}
    for item in items:
        url = urlsplit(item.link)
        match = re.fullmatch(r"/update-guide/(?:[a-z]{2}-[A-Z]{2}/)?vulnerability/(CVE-\d{4}-\d{4,})", url.path)
        if url.scheme != "https" or url.netloc != "msrc.microsoft.com" or match is None:
            continue
        cve = match.group(1)
        if item.guid and item.guid != cve:
            continue
        try:
            revision = Decimal(item.attributes.get("Revision", "0"))
            if not revision.is_finite():
                revision = Decimal(0)
        except InvalidOperation:
            revision = Decimal(0)
        position = (item.published_at or "", revision)
        if cve not in selected or position > selected[cve][0]:
            selected[cve] = (position, item)
    if items and not selected:
        raise ValueError("MSRC RSS contains no valid CVE links")
    entries = []
    for cve, (_, item) in sorted(selected.items(), key=lambda pair: pair[1][0], reverse=True):
        entries.append(ListEntry(
            VulnerabilityId("MSRC", cve.removeprefix("CVE-")), item.title, None,
            item.published_at, None, provider, source_url,
            {"_list_summary": True, "updated_at": item.published_at,
             "rss_revision": item.attributes.get("Revision"), "detail_url": item.link},
        ))
    return ListPage(page, entries, total_pages=1, total_records=len(entries), exhausted=not items)
