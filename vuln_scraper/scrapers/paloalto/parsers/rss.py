from __future__ import annotations

import re
from urllib.parse import urlsplit

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.rss import parse_rss
from vuln_scraper.scrapers.paloalto.config import SOURCE_URL


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str = SOURCE_URL) -> ListPage:
    items = parse_rss(xml, source="Palo Alto")
    entries = []
    seen = set()
    for item in items:
        url = urlsplit(item.link)
        code = url.path.strip("/")
        if (url.scheme != "https" or url.netloc != "security.paloaltonetworks.com"
                or not re.fullmatch(r"(?:CVE|PAN-SA)-\d{4}-\d+", code) or code in seen):
            continue
        seen.add(code)
        severity = re.search(r"\(Severity:\s*(\w+)\)\s*$", item.title, re.IGNORECASE)
        title = re.sub(r"\s*\(Severity:[^)]*\)\s*$", "", item.title, flags=re.IGNORECASE)
        entries.append(ListEntry(
            VulnerabilityId("PALOALTO", code), title, None, item.published_at, None,
            provider, source_url, {"_list_summary": True, "published_at": item.published_at,
                                   "severity": severity.group(1) if severity else None},
        ))
    if items and not entries:
        raise ValueError("Palo Alto RSS contains no valid advisory links")
    return ListPage(page, entries, total_pages=1, total_records=len(entries), exhausted=not items)
