from __future__ import annotations

import re
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.splunk.config import BASE_URL, SOURCE_URL
from vuln_scraper.scrapers.splunk.parsers.common import clean_text, cve_ids_from_text, soup


ADVISORY_PATH = re.compile(r"/advisories/(SVD-\d{4}-\d{4,})/?", re.IGNORECASE)


def parse_advisory_list(
    xml: str,
    *,
    page: int,
    provider: str = "splunk",
    source_url: str = SOURCE_URL,
) -> ListPage:
    root = ElementTree.fromstring(xml)
    channel = root.find("{*}channel") if root.tag.rsplit("}", 1)[-1] == "rss" else None
    if channel is None:
        raise ValueError("Splunk feed must contain an RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = channel.findall("{*}item")
    for item in items:
        code = _advisory_code(item.findtext("{*}link", "").strip())
        if code is None or code in seen:
            continue
        seen.add(code)

        title = " ".join(item.findtext("{*}title", "").split())
        prefix, sep, rest = title.partition(":")
        if sep and prefix.strip().upper() == code:
            title = rest.strip()
        description = clean_text(soup(item.findtext("{*}description", ""))) or None
        published_date = _publication_date(item.findtext("{*}pubDate", "").strip())
        cve_ids = cve_ids_from_text(f"{title}\n{description or ''}")
        entries.append(ListEntry(
            identity=VulnerabilityId(type="SPLUNK", code=code),
            title=title or code,
            vuln_type=None,
            disclosure_date=published_date,
            status=None,
            provider=provider,
            source_url=source_url,
            embedded_detail={
                "_list_summary": True,
                "advisory_id": code,
                "description": description,
                "cve_id": cve_ids[0] if cve_ids else None,
                "cve_ids": cve_ids,
            },
        ))

    if items and not entries:
        raise ValueError("Splunk feed did not contain valid advisory links")
    return ListPage(page=page, entries=entries, total_pages=1,
                    total_records=len(entries), exhausted=not items)


def _advisory_code(link: str) -> str | None:
    try:
        target = urlsplit(urljoin(BASE_URL, link))
    except ValueError:
        return None
    if target.scheme != "https" or target.netloc.lower() != urlsplit(BASE_URL).netloc:
        return None
    match = ADVISORY_PATH.fullmatch(target.path)
    return match.group(1).upper() if match else None


def _publication_date(value: str) -> str | None:
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError, OverflowError):
        return None
