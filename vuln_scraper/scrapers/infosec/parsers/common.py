from __future__ import annotations

import re
from datetime import datetime

from bs4 import BeautifulSoup


DATE_RE = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$")


def soup(html: str) -> BeautifulSoup:
    safe_html = html.encode("utf-8", "replace").decode("utf-8", "replace")
    return BeautifulSoup(safe_html, "lxml")


def clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).replace("\ufeff", "").split())


def normalize_infosec_date(value: str | None) -> str | None:
    if not value:
        return None
    text = " ".join(value.replace("\xa0", " ").split())
    match = DATE_RE.match(text)
    if match:
        year, month, day = (int(part) for part in match.groups())
        return datetime(year, month, day).date().isoformat()
    return text or None
