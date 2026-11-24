from __future__ import annotations

import re
from urllib.parse import urlsplit

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.rss import parse_rss, warn_if_stale
from vuln_scraper.scrapers.huawei_sa.config import SOURCE_URL


def advisory_url(value: str) -> str | None:
    url = urlsplit(value.strip())
    legacy = url.netloc == "www.huawei.com" and re.fullmatch(
        r"/en/psirt/security-advisories/\d{4}/[A-Za-z0-9-]+", url.path)
    current = url.netloc == "securitybulletin.huawei.com" and re.fullmatch(
        r"/enterprise/en/sa/detail/[A-Za-z0-9-]+", url.path)
    if url.scheme != "https" or not (legacy or current):
        return None
    return url._replace(query="", fragment="").geturl()


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str = SOURCE_URL) -> ListPage:
    items = parse_rss(xml, source="Huawei SA")
    warn_if_stale(items, source="Huawei SA")
    entries = []
    seen = set()
    for item in items:
        url = advisory_url(item.link)
        if not url:
            continue
        code = urlsplit(url).path.rsplit("/", 1)[-1]
        if code in seen:
            continue
        seen.add(code)
        entries.append(ListEntry(
            VulnerabilityId("HUAWEI_SA", code), item.title, None, item.published_at, "NEW",
            provider, source_url, {"_list_summary": True, "published_at": item.published_at,
                                   "detail_url": url},
        ))
    if items and not entries:
        raise ValueError("Huawei SA RSS contains no valid security advisory links")
    return ListPage(page, entries, total_pages=1, total_records=len(entries), exhausted=not items)
