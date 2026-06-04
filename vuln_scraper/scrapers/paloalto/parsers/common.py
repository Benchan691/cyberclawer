from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)


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


def clean_multiline(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text("\n", strip=True)
    else:
        text = str(node)
    lines = [normalize_space(line) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def iso_date(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    match = re.search(r"\d{4}-\d{2}-\d{2}", text)
    return match.group(0) if match else None


def cve_ids_from_text(value: str) -> list[str]:
    seen: set[str] = set()
    cves: list[str] = []
    for match in CVE_RE.findall(value):
        cve = match.upper()
        if cve not in seen:
            cves.append(cve)
            seen.add(cve)
    return cves


def unique_links(nodes, *, base_url: str) -> list[str]:
    links: list[str] = []
    for node in nodes:
        href = node.get("href") if isinstance(node, Tag) else None
        if not href or href.startswith(("mailto:", "javascript:")):
            continue
        url = urljoin(base_url, href)
        if url not in links:
            links.append(url)
    return links
