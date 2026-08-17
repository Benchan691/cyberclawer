from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
IR_CODE_RE = re.compile(r"\bFG-IR-\d{2}-\d+\b", re.IGNORECASE)
CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[A-Za-z0-9:./]+", re.IGNORECASE)


def soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "lxml")


def clean_text(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        text = node
    elif isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    return normalize_space(text)


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def iso_date(value: str | None) -> str | None:
    text = normalize_space(value or "")
    if not text:
        return None
    match = re.search(r"\d{4}-\d{2}-\d{2}", text)
    if match:
        return match.group(0)
    for fmt in ("%b %d, %Y", "%B %d, %Y", "%d %b %Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def cve_ids_from_text(value: str) -> list[str]:
    seen: set[str] = set()
    cves: list[str] = []
    for match in CVE_RE.findall(value or ""):
        cve = match.upper()
        if cve not in seen:
            cves.append(cve)
            seen.add(cve)
    return cves


def absolute_url(href: str | None, *, base_url: str) -> str | None:
    text = (href or "").strip()
    if not text or text.startswith(("mailto:", "javascript:")):
        return None
    return urljoin(base_url, text)
