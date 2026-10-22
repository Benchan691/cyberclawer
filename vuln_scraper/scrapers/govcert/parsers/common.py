from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urljoin

from bs4 import BeautifulSoup


ALERT_TITLE_RE = re.compile(r"^(?P<type>.+?)\s+\((?P<code>A\d{2}-\d{2}-\d{2})\):\s*(?P<title>.+)$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DATE_FORMATS = ("%d-%B-%Y", "%d %B %Y", "%d-%b-%Y", "%d %b %Y")


def soup(html: str) -> BeautifulSoup:
    safe_html = html.encode("utf-8", "replace").decode("utf-8", "replace")
    return BeautifulSoup(safe_html, "lxml")


def clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).replace("\ufeff", "").split())


def clean_multiline(node) -> str:
    if node is None:
        return ""
    lines = [line.strip().replace("\ufeff", "") for line in node.get_text("\n", strip=True).splitlines()]
    return "\n".join(line for line in lines if line and line != "\xa0")


def normalize_date(value: str | None) -> str | None:
    if not value:
        return None
    text = " ".join(value.replace("\xa0", " ").split())
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    return text or None


def parse_alert_title(title: str) -> tuple[str | None, str | None, str]:
    clean_title = " ".join(title.replace("\ufeff", "").split())
    match = ALERT_TITLE_RE.match(clean_title)
    if not match:
        return None, None, clean_title
    return match.group("code"), match.group("type").strip(), clean_title


def unique_links(links, *, base_url: str) -> list[str]:
    result: list[str] = []
    for link in links:
        href = link.get("href")
        if not href:
            continue
        url = urljoin(base_url, str(href))
        if url not in result:
            result.append(url)
    return result


def cve_ids_from_text(text: str) -> list[str]:
    ids: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in ids:
            ids.append(normalized)
    return ids
