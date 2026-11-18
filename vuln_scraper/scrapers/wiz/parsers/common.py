from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from html import unescape
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from vuln_scraper.scrapers.wiz.config import BASE_URL


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def clean_text(html: str) -> str:
    if "<" in html and ">" in html:
        soup = BeautifulSoup(html, "lxml")
        for node in soup.find_all(("br", "p", "div", "li")):
            node.insert_after(" ")
        html = soup.get_text()
    return " ".join(unescape(html).split())


def incident_url(value: str) -> str | None:
    url = urljoin(f"{BASE_URL}/", value.strip())
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.netloc != "threats.wiz.io"
            or not re.fullmatch(r"/all-incidents/[^/]+/?", parsed.path)):
        return None
    return parsed._replace(query="", fragment="").geturl().rstrip("/")


def cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in CVE_RE.findall(text)))


def normalized_date(value: str) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        parsed = None
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%B %d, %Y", "%b %d, %Y", "%b %d, %Y %I:%M %p", "%B %d, %Y %I:%M %p"):
                try:
                    parsed = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
    if parsed is None:
        return None
    # The RSS dates and server-rendered Notion properties use UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()
