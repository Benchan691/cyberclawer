from __future__ import annotations

import re
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.fortiguard.config import SOURCE_URL
from vuln_scraper.scrapers.fortiguard.parsers.common import (
    IR_CODE_RE,
    clean_multiline,
    cve_ids_from_text,
    iso_date,
    soup,
)

ADVISORY_HOSTS = {"www.fortiguard.com", "fortiguard.com", "fortiguard.fortinet.com"}
REVISED_RE = re.compile(r"Revised\s+on\s+(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def parse_rss_list(
    xml: str,
    *,
    page: int,
    provider: str = "fortiguard",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    """Parse Fortinet's latest-advisory feed, including its namespaced links."""
    root = ElementTree.fromstring(xml)
    channel = root.find("channel") if root.tag == "rss" else None
    if channel is None:
        raise ValueError("FortiGuard PSIRT feed must contain an RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = channel.findall("item")
    for item in items:
        link = (item.findtext("link") or item.findtext("guid") or "").strip()
        target = urlparse(link)
        code = target.path.removeprefix("/psirt/").upper()
        if (
            target.scheme not in {"http", "https"}
            or target.netloc.lower() not in ADVISORY_HOSTS
            or not target.path.startswith("/psirt/")
            or not IR_CODE_RE.fullmatch(code)
            or code in seen
        ):
            continue

        title = (item.findtext("title") or code).strip() or code
        summary = clean_multiline(soup(item.findtext("description") or ""))
        revised = REVISED_RE.search(summary)
        try:
            published = parsedate_to_datetime(item.findtext("pubDate") or "").date().isoformat()
        except (TypeError, ValueError, OverflowError):
            published = iso_date(item.findtext("pubDate"))
        updated = revised.group(1) if revised else published

        download_links: dict[str, str] = {}
        for child in item:
            namespace, _, name = child.tag.rpartition("}")
            if name != "link" or not child.text:
                continue
            if namespace.endswith("/csaf"):
                download_links["csaf_url"] = child.text.strip()
            elif namespace.endswith("/cvrf"):
                download_links["cvrf_url"] = child.text.strip()

        seen.add(code)
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="FORTIGUARD", code=code),
                title=title,
                vuln_type=None,
                disclosure_date=published,
                status=None,
                provider=provider,
                source_url=source_url,
                embedded_detail={
                    "_list_summary": True,
                    "advisory_id": code,
                    "title": title,
                    "summary": summary or None,
                    "published_date": published,
                    "updated_date": updated,
                    "cve_ids": cve_ids_from_text(f"{title}\n{summary}"),
                    **download_links,
                },
            )
        )

    if items and not entries:
        raise ValueError("FortiGuard PSIRT feed did not contain valid advisory links")

    # Old advisories may be revised; preserve newest-update ordering for catch-up.
    entries.sort(key=lambda entry: entry.embedded_detail.get("updated_date") or "", reverse=True)
    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        start_index=0,
        results_per_page=len(entries),
        exhausted=not entries,
    )
