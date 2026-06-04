from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.hikvision.config import BASE_URL


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
DATE_RE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{4}|[A-Z][a-z]+ \d{1,2}, \d{4}")


@dataclass(slots=True)
class HikvisionDetailRecord:
    advisory_id: str | None = None
    title: str | None = None
    published_date: str | None = None
    updated_date: str | None = None
    severity: str | None = None
    summary: str | None = None
    description: str | None = None
    affected_products: list[str] = field(default_factory=list)
    solution: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> HikvisionDetailRecord:
    parsed = _soup(html)
    text = _clean_multiline(parsed)
    sections = _sections(parsed)
    title = _title(parsed)
    cve_ids = _cve_ids(text)
    return HikvisionDetailRecord(
        advisory_id=_advisory_id(parsed, title),
        title=title,
        published_date=_date_from_labels(text, ("published", "release date", "date")),
        updated_date=_date_from_labels(text, ("updated", "last updated", "update date")),
        severity=_severity(text),
        summary=_summary(parsed),
        description=_section_by_names(sections, ("description", "overview", "summary")) or text or None,
        affected_products=_lines(_section_by_names(sections, ("affected products", "affected versions", "affected product"))),
        solution=_section_by_names(sections, ("solution", "remediation", "mitigation", "recommendation")),
        cve_ids=cve_ids,
        reference_links=_reference_links(parsed),
        raw_sections=sections,
    )


def _title(parsed: BeautifulSoup) -> str | None:
    for selector in ("h1", ".page-title", ".article-title", "h2", "title"):
        text = _clean_text(parsed.select_one(selector))
        if text:
            return text
    return None


def _advisory_id(parsed: BeautifulSoup, title: str | None) -> str | None:
    text = "\n".join([title or "", _clean_multiline(parsed)])
    for pattern in (r"\bHSRC-\d{4}-\d+\b", r"\bHIKVISION[-\s]SA[-\s]\d{4}[-\s]\d+\b"):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0).upper().replace(" ", "-")
    return None


def _sections(parsed: BeautifulSoup) -> dict[str, str]:
    sections: dict[str, str] = {}
    for heading in parsed.find_all(["h2", "h3", "h4"]):
        key = _normalize_key(_clean_text(heading).rstrip(":"))
        if not key:
            continue
        chunks: list[str] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name in {"h2", "h3", "h4"}:
                    break
                text = _clean_multiline(sibling)
                if text:
                    chunks.append(text)
        if chunks:
            sections[key] = "\n".join(chunks).strip()
    return sections


def _section_by_names(sections: dict[str, str], names: tuple[str, ...]) -> str | None:
    normalized = {_normalize_key(name) for name in names}
    for key, value in sections.items():
        if key in normalized:
            return value
    return None


def _date_from_labels(text: str, labels: tuple[str, ...]) -> str | None:
    lowered = text.casefold()
    for label in labels:
        index = lowered.find(label)
        if index < 0:
            continue
        match = DATE_RE.search(text[index : index + 120])
        if match:
            return _iso_date(match.group(0))
    match = DATE_RE.search(text)
    return _iso_date(match.group(0)) if match and "date" in labels else None


def _severity(text: str) -> str | None:
    upper = text.upper()
    for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if value in upper:
            return value.title()
    return None


def _summary(parsed: BeautifulSoup) -> str | None:
    for paragraph in parsed.find_all("p"):
        text = _clean_text(paragraph)
        if text and len(text) > 40:
            return text
    return None


def _reference_links(parsed: BeautifulSoup) -> list[str]:
    links: list[str] = []
    for link in parsed.find_all("a", href=True):
        href = str(link.get("href") or "").strip()
        if href and not href.startswith(("mailto:", "javascript:")):
            url = urljoin(BASE_URL, href)
            if url not in links:
                links.append(url)
    return links


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


def _lines(value: str | None) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "-" in text:
        year, month, day = text.split("-")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    if "/" in text:
        month, day, year = text.split("/")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return text


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _clean_text(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    return " ".join(text.replace("\xa0", " ").split())


def _clean_multiline(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text("\n", strip=True)
    else:
        text = str(node)
    lines = [" ".join(line.replace("\xa0", " ").split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")
