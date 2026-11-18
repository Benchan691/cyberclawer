from __future__ import annotations

import re
from uuid import UUID
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.wiz.config import SOURCE_URL
from vuln_scraper.scrapers.wiz.parsers.common import clean_text, cve_ids, incident_url, normalized_date


TYPE_SUFFIX_RE = re.compile(r"\s+\((Campaign|Incident|Research)\)$", re.IGNORECASE)


def parse_rss_list(
    xml: str, *, page: int, provider: str = "wiz", source_url: str = SOURCE_URL,
) -> ListPage:
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, TypeError, ValueError) as exc:
        raise ValueError("Invalid Wiz Cloud Threat Landscape RSS feed") from exc
    channel = next((child for child in root if _local_name(child.tag) == "channel"), None)
    if _local_name(root.tag) != "rss" or channel is None:
        raise ValueError("Wiz RSS feed is missing its RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = [item for item in channel if _local_name(item.tag) == "item"]
    for item in items:
        fields = {_local_name(child.tag): "".join(child.itertext()).strip() for child in item}
        try:
            code = str(UUID(fields.get("guid", "")))
        except ValueError:
            continue
        url = incident_url(fields.get("link", ""))
        raw_title = clean_text(fields.get("title", ""))
        if not url or not raw_title or code in seen:
            continue
        seen.add(code)
        type_match = TYPE_SUFFIX_RE.search(raw_title)
        threat_type = type_match.group(1).title() if type_match else None
        title = TYPE_SUFFIX_RE.sub("", raw_title)
        published_at = normalized_date(fields.get("pubDate", ""))
        summary = clean_text(fields.get("encoded") or fields.get("description", ""))
        entries.append(ListEntry(
            identity=VulnerabilityId(type="WIZ", code=code),
            title=title,
            vuln_type=threat_type,
            disclosure_date=published_at[:10] if published_at else None,
            status=None,
            provider=provider,
            source_url=source_url,
            embedded_detail={
                "_list_summary": True,
                "feed_guid": code,
                "title": title,
                "article_url": url,
                "threat_type": threat_type,
                "published_at": published_at,
                "summary": summary or None,
                "author": fields.get("author") or fields.get("creator") or None,
                "cve_ids": cve_ids(f"{title}\n{summary}"),
                "reference_links": [url],
            },
        ))
    if items and not entries:
        raise ValueError("Wiz RSS feed contains items but no valid incident entries")
    return ListPage(page=page, entries=entries, total_pages=1, total_records=len(entries),
                    start_index=0, results_per_page=len(entries), exhausted=not items)


def _local_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]
