from __future__ import annotations

from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.rss import parse_rss, warn_if_stale
from vuln_scraper.scrapers.zimbra.config import BASE_URL, SOURCE_URL
from vuln_scraper.scrapers.zimbra.parsers.list import _patch_code


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str = SOURCE_URL) -> ListPage:
    items = parse_rss(xml, source="Zimbra")
    warn_if_stale(items, source="Zimbra")
    releases = {}
    valid_posts = 0
    for item in items:
        post = urlsplit(item.link)
        if post.scheme != "https" or post.netloc != "blog.zimbra.com":
            continue
        valid_posts += 1
        body = BeautifulSoup(item.content or item.description, "lxml")
        for anchor in body.select("a[href]"):
            url = urlsplit(str(anchor["href"]))
            if url.scheme not in {"https", "http"} or url.netloc != "wiki.zimbra.com":
                continue
            code = _patch_code(url.geturl())
            if code is None:
                continue
            priority = (code in item.title, item.published_at or "")
            if code not in releases or priority > releases[code][0]:
                releases[code] = (priority, item)
    if items and not valid_posts:
        raise ValueError("Zimbra RSS contains no official blog posts")
    entries = []
    for code, (_, item) in releases.items():
        entries.append(ListEntry(
            VulnerabilityId("ZIMBRA", code), f"Zimbra {code} Patch Release", "Patch Release",
            item.published_at, "Patch Release", provider, source_url,
            {"_list_summary": True, "version": code, "published_at": item.published_at,
             "reference_links": [f"{BASE_URL}/wiki/Zimbra_Releases/{code}"]},
        ))
    return ListPage(page, entries, total_pages=1, total_records=len(entries), exhausted=not entries)
