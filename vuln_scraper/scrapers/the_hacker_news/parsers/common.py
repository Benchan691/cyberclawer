from __future__ import annotations

import re
from datetime import UTC
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from vuln_scraper.timestamps import parse_timestamp


ARTICLE_PATH = re.compile(r"/(\d{4})/(0[1-9]|1[0-2])/([a-z0-9]+(?:-[a-z0-9]+)*)\.html")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def clean_text(value: str) -> str:
    return " ".join(BeautifulSoup(value, "lxml").get_text(" ", strip=True).split())


def article_url(value: str) -> str | None:
    parsed = urlparse(value.strip())
    if (parsed.scheme not in {"http", "https"}
            or parsed.netloc.lower() not in {"thehackernews.com", "www.thehackernews.com"}
            or not ARTICLE_PATH.fullmatch(parsed.path)):
        return None
    return f"https://thehackernews.com{parsed.path}"


def article_code(url: str) -> str:
    normalized = article_url(url)
    if normalized is None:
        raise ValueError(f"Invalid The Hacker News article URL: {url!r}")
    return "-".join(ARTICLE_PATH.fullmatch(urlparse(normalized).path).groups())


def cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in CVE_RE.findall(text)))


def normalized_date(value: str) -> str | None:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        parsed = parse_timestamp(value)
    return parsed.astimezone(UTC).isoformat() if parsed is not None else None
