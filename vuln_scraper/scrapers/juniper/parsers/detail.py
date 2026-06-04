from __future__ import annotations

import html as html_module
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.juniper.config import BASE_URL


ARTICLE_ID_RE = re.compile(r"\bJSA\d{5,}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
DATE_RE = re.compile(r"\d{4}-\d{1,2}-\d{1,2}|[A-Z][a-z]+ \d{1,2}, \d{4}")


@dataclass(slots=True)
class JuniperDetailRecord:
    article_id: str | None = None
    title: str | None = None
    article_type: str | None = None
    source_name: str | None = None
    published_date: str | None = None
    updated_date: str | None = None
    summary: str | None = None
    description: str | None = None
    solution: str | None = None
    workaround: str | None = None
    products: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    raw_fields: dict[str, str | None] = field(default_factory=dict)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> JuniperDetailRecord:
    parsed = _soup(html)
    text = _clean_multiline(parsed)
    fields = _fields(parsed)
    sections = _sections(parsed)
    title = _title(parsed)

    return JuniperDetailRecord(
        article_id=_article_id(text, title),
        title=title,
        article_type=fields.get("article_type") or "Security Advisories",
        source_name=fields.get("source_name") or "Knowledge",
        published_date=_date_field(fields, text, ("published", "created", "publication_date")),
        updated_date=_date_field(fields, text, ("updated", "last_modified", "modified_date")),
        summary=_summary(parsed),
        description=_section_by_names(sections, ("description", "problem", "summary")) or text or None,
        solution=_section_by_names(sections, ("solution", "resolution")),
        workaround=_section_by_names(sections, ("workaround", "mitigation")),
        products=_lines(_section_by_names(sections, ("product affected", "affected products", "products affected"))),
        cve_ids=_cve_ids(text),
        reference_links=_reference_links(parsed),
        raw_fields=fields,
        raw_sections=sections,
    )


def _title(parsed: BeautifulSoup) -> str | None:
    for selector in ("h1", ".article-headline", ".test-id__field-value", "title"):
        text = _clean_text(parsed.select_one(selector))
        if text:
            return text
    return None


def _article_id(text: str, title: str | None) -> str | None:
    match = ARTICLE_ID_RE.search("\n".join([title or "", text]))
    return match.group(0).upper() if match else None


def _fields(parsed: BeautifulSoup) -> dict[str, str | None]:
    fields: dict[str, str | None] = {}
    for row in parsed.find_all(["dl", "tr"]):
        if row.name == "dl":
            labels = row.find_all("dt")
            values = row.find_all("dd")
            for label, value in zip(labels, values, strict=False):
                key = _normalize_key(_clean_text(label))
                if key:
                    fields[key] = _clean_text(value) or None
        elif row.name == "tr":
            cells = row.find_all(["th", "td"], recursive=False)
            if len(cells) == 2:
                key = _normalize_key(_clean_text(cells[0]))
                if key:
                    fields[key] = _clean_text(cells[1]) or None
    return fields


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
                if sibling.name == "a":
                    continue
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


def _date_field(fields: dict[str, str | None], text: str, names: tuple[str, ...]) -> str | None:
    for name in names:
        value = fields.get(_normalize_key(name))
        if value:
            return _iso_date(value)
    lowered = text.casefold()
    for name in names:
        index = lowered.find(name.replace("_", " "))
        if index < 0:
            continue
        match = DATE_RE.search(text[index : index + 120])
        if match:
            return _iso_date(match.group(0))
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


def strip_html(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = str(text)
    cleaned = re.sub(r"<br\s*/?>", "\n", cleaned, flags=re.I)
    cleaned = re.sub(r"</p>", "\n\n", cleaned, flags=re.I)
    cleaned = re.sub(r"</li>", "\n", cleaned, flags=re.I)
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    cleaned = html_module.unescape(cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned or None


def _lines(value: str | None) -> list[str]:
    if not value:
        return []
    stripped = strip_html(value) or value
    return [line.strip() for line in stripped.splitlines() if line.strip()]


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    match = DATE_RE.search(text)
    if not match:
        return text or None
    found = match.group(0)
    if "-" in found:
        year, month, day = found.split("-")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    return found


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


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
