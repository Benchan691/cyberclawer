from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


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


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def cve_ids_from_text(text: str) -> list[str]:
    ids: list[str] = []
    for cve_id in CVE_RE.findall(text or ""):
        normalized = cve_id.upper()
        if normalized not in ids:
            ids.append(normalized)
    return ids


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
