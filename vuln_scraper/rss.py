"""Small, strict RSS reader shared by providers that discover records in XML."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree

from .timestamps import parse_timestamp


@dataclass(slots=True)
class RSSItem:
    title: str
    link: str
    guid: str
    published_at: str | None
    description: str
    content: str
    attributes: dict[str, str]


def rss_date(value: str) -> str | None:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        parsed = parse_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parse_timestamp(parsed)
    return parsed.astimezone(UTC).isoformat()


def parse_rss(xml: str, *, source: str) -> list[RSSItem]:
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, ValueError, TypeError) as exc:
        raise ValueError(f"Invalid {source} RSS feed") from exc
    def name(tag: object) -> str:
        return str(tag).rsplit("}", 1)[-1]

    channel = next((node for node in root if name(node.tag) == "channel"), None)
    if name(root.tag) != "rss" or channel is None:
        raise ValueError(f"{source} RSS feed is missing its channel")
    raw_items = [node for node in channel if name(node.tag) == "item"]
    items = []
    for node in raw_items:
        fields = {name(child.tag): "".join(child.itertext()).strip() for child in node}
        title = " ".join(fields.get("title", "").split())
        link = fields.get("origLink") or fields.get("link") or fields.get("guid", "")
        if not title or not link:
            continue
        items.append(RSSItem(title, link, fields.get("guid", ""),
                             rss_date(fields.get("pubDate", "")), fields.get("description", ""),
                             fields.get("encoded", ""), dict(node.attrib)))
    if raw_items and not items:
        raise ValueError(f"{source} RSS feed contains items but no valid entries")
    return items


def warn_if_stale(items: list[RSSItem], *, source: str) -> None:
    dates = [parse_timestamp(item.published_at) for item in items if item.published_at]
    latest = max((date for date in dates if date is not None), default=None)
    if latest is not None and latest < datetime.now(UTC) - timedelta(days=30):
        logging.getLogger(__name__).warning(
            "%s RSS coverage may be stale: newest feed timestamp is %s; "
            "only records exposed by RSS can be discovered; no listing fallback is used",
            source, latest.isoformat(),
        )
