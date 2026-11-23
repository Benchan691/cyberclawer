from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree.ElementTree import Element

from bs4 import BeautifulSoup

from ..config import ARTICLE_BASE_URL


ARTICLE_CODE_RE = re.compile(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+")
CREATOR_TAG = "{http://purl.org/dc/elements/1.1/}creator"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class BleepingComputerDetailRecord:
    code: str
    title: str
    published_at: datetime
    summary: str | None
    author: str | None
    categories: list[str]
    cve_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "published_at": self.published_at.isoformat(),
            "summary": self.summary,
            "author": self.author,
            "categories": self.categories,
            "cve_ids": self.cve_ids,
        }


def _article_code(item: Element) -> str:
    for tag in ("link", "guid"):
        url = item.findtext(tag, "").strip().partition("?")[0].partition("#")[0]
        if url.startswith(ARTICLE_BASE_URL):
            code = url.removeprefix(ARTICLE_BASE_URL).removesuffix("/")
            if ARTICLE_CODE_RE.fullmatch(code):
                return code
    raise ValueError("Missing BleepingComputer article URL")


def parse_rss_item(item: Element) -> BleepingComputerDetailRecord:
    title = " ".join(item.findtext("title", "").split())
    if item.tag != "item" or not title:
        raise ValueError("Missing BleepingComputer RSS item or title")
    published = parsedate_to_datetime(item.findtext("pubDate", "").strip())
    if published.tzinfo is None:
        published = published.replace(tzinfo=UTC)
    summary_html = item.findtext("description", "")
    summary = " ".join(BeautifulSoup(summary_html, "html.parser").get_text(" ", strip=True).split())
    author = " ".join(item.findtext(CREATOR_TAG, "").split())
    categories = (" ".join(node.itertext()).strip() for node in item.findall("category"))
    return BleepingComputerDetailRecord(
        code=_article_code(item),
        title=title,
        published_at=published.astimezone(UTC),
        summary=summary or None,
        author=author or None,
        categories=list(dict.fromkeys(category for category in categories if category)),
        cve_ids=list(dict.fromkeys(match.upper() for match in CVE_RE.findall(f"{title} {summary}"))),
    )
