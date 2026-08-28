from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.hpe.config import SOURCE_URL


DOC_DISPLAY_PATH = "/hpesc/public/docdisplay"
MAX_RSS_ENTRIES = 50
DOC_ID_SUFFIX_RE = re.compile(r"en_us$", re.IGNORECASE)
HPE_BULLETIN_RE = re.compile(r"\b(HPESB[A-Z0-9]+)\b", re.IGNORECASE)


def parse_rss_list(
    xml: str,
    *,
    page: int,
    provider: str = "hpe",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    """Parse HPE's namespace-qualified security bulletin RSS feed."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, TypeError, ValueError):
        return ListPage(page=page, entries=[], total_pages=1, total_records=0)

    entries: list[ListEntry] = []
    seen_doc_ids: set[str] = set()
    item_count = 0
    for item in root.iter():
        if _local_name(item.tag) != "item":
            continue
        if item_count >= MAX_RSS_ENTRIES:
            break
        item_count += 1

        title = _element_text(item, "title")
        link = _element_text(item, "link")
        guid = _element_text(item, "guid")
        doc_display_url = _doc_display_url(link) or _doc_display_url(guid)
        doc_id = _doc_id(doc_display_url)
        if not doc_id or doc_id in seen_doc_ids:
            continue

        seen_doc_ids.add(doc_id)
        published_date, published_at = _published_date(_element_text(item, "pubDate"))
        bulletin_id = _bulletin_id(title, doc_id)
        description = _element_text(item, "description")
        creator = _element_text(item, "creator")
        entry_title = title or bulletin_id or doc_id
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="HPE", code=doc_id),
                title=entry_title,
                vuln_type="Security Bulletin",
                disclosure_date=published_date,
                status="Critical",
                provider=provider,
                source_url=source_url,
                embedded_detail={
                    "_list_summary": True,
                    "bulletin_id": bulletin_id,
                    "doc_id": doc_id,
                    "doc_display_url": doc_display_url,
                    "published_date": published_date,
                    "published_at": published_at,
                    "severity": "Critical",
                    "creator": creator or None,
                    "summary": description or None,
                    "description": description or None,
                    "feed_guid": guid or None,
                    "reference_links": [doc_display_url],
                },
            )
        )

    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        start_index=0,
        results_per_page=len(entries),
    )


def parse_security_bulletin_feed(
    xml: str,
    *,
    page: int,
    provider: str = "hpe",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    """Backward-friendly alias for callers that describe the feed by purpose."""
    return parse_rss_list(xml, page=page, provider=provider, source_url=source_url)


def _element_text(item: ElementTree.Element, name: str) -> str:
    wanted = name.casefold()
    for child in list(item):
        if _local_name(child.tag).casefold() == wanted:
            return " ".join("".join(child.itertext()).split())
    return ""


def _local_name(tag: object) -> str:
    value = str(tag)
    return value.rsplit("}", 1)[-1]


def _doc_display_url(value: str) -> str | None:
    candidate = value.strip()
    parsed = urlparse(candidate)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or parsed.netloc.casefold() != "support.hpe.com"
        or parsed.path.casefold() != DOC_DISPLAY_PATH
    ):
        return None
    if not _query_value(parsed.query, "docid"):
        return None
    return candidate


def _doc_id(doc_display_url: str | None) -> str | None:
    if not doc_display_url:
        return None
    parsed = urlparse(doc_display_url)
    value = _query_value(parsed.query, "docid")
    return value.casefold() if value else None


def _query_value(query: str, wanted: str) -> str | None:
    for key, values in parse_qs(query, keep_blank_values=False).items():
        if key.casefold() == wanted.casefold() and values and values[0].strip():
            return values[0].strip()
    return None


def _published_date(value: str) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        parsed = None
    if parsed is not None:
        return parsed.date().isoformat(), parsed.isoformat()

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None, None
    return parsed.date().isoformat(), parsed.isoformat()


def _bulletin_id(title: str, doc_id: str) -> str:
    match = HPE_BULLETIN_RE.search(title or "")
    if match:
        return match.group(1).upper()
    return DOC_ID_SUFFIX_RE.sub("", doc_id).upper()
