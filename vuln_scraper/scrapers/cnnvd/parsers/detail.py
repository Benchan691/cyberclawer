from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.cnnvd.config import BASE_URL


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"]+")
SECTION_RE = re.compile(r"^[一二三四五六七八九十]+[、.．]\s*(.+)$")


@dataclass(slots=True)
class CNNVDDetailRecord:
    warn_id: str | None = None
    title: str | None = None
    alert_type: str | None = None
    published_date: str | None = None
    created_by: str | None = None
    summary: str | None = None
    description: str | None = None
    severity_counts: dict[str, int] = field(default_factory=dict)
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_warn_detail(data: Any) -> CNNVDDetailRecord:
    payload = _coerce_json(data)
    item = _detail_payload(payload)
    html = _optional_str(item.get("enclosureContent") or item.get("content") or item.get("contentStr")) or ""
    parsed = _soup(html)
    body_text = _clean_multiline(parsed)
    title = _optional_str(item.get("warnName") or item.get("title")) or _title_from_body(parsed)
    alert_type, clean_title = _title_parts(title)
    sections = _sections(parsed)
    full_text = "\n".join([clean_title or "", body_text])

    return CNNVDDetailRecord(
        warn_id=_optional_str(item.get("warnId") or item.get("id")),
        title=clean_title,
        alert_type=alert_type,
        published_date=_iso_date(_optional_str(item.get("publishTime") or item.get("published"))),
        created_by=_optional_str(item.get("createUname")),
        summary=_first_paragraph(parsed),
        description=body_text or None,
        severity_counts=_severity_counts(body_text),
        cve_ids=_cve_ids(full_text),
        reference_links=_reference_links(parsed, body_text),
        raw_sections=sections,
        raw=dict(item),
    )


def _detail_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict):
            return dict(data)
        if payload.get("warnName") or payload.get("enclosureContent"):
            return dict(payload)
    raise ValueError("CNNVD detail response did not contain a warning object")


def _sections(parsed: BeautifulSoup) -> dict[str, str]:
    lines = [line.strip() for line in _clean_multiline(parsed).splitlines() if line.strip()]
    sections: dict[str, list[str]] = {}
    current_key: str | None = None
    for line in lines:
        match = SECTION_RE.match(line)
        if match:
            current_key = _normalize_key(match.group(1))
            sections.setdefault(current_key, [])
            continue
        if current_key:
            sections[current_key].append(line)
    return {key: "\n".join(value).strip() for key, value in sections.items() if any(value)}


def _reference_links(parsed: BeautifulSoup, text: str) -> list[str]:
    links: list[str] = []
    for link in parsed.find_all("a", href=True):
        href = str(link.get("href") or "").strip()
        if href and not href.startswith(("mailto:", "javascript:")):
            url = urljoin(BASE_URL, href)
            if url not in links:
                links.append(url)
    for match in URL_RE.findall(text):
        url = match.rstrip(").,;，。")
        if url not in links:
            links.append(url)
    return links


def _severity_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in ("超危", "高危", "中危", "低危"):
        match = re.search(rf"{label}漏洞\s*(\d+)\s*个", text)
        if match:
            counts[label] = int(match.group(1))
    return counts


def _first_paragraph(parsed: BeautifulSoup) -> str | None:
    for paragraph in parsed.find_all("p"):
        text = _clean_text(paragraph)
        if text and not SECTION_RE.match(text):
            return text
    return None


def _title_from_body(parsed: BeautifulSoup) -> str | None:
    for selector in ("h1", "h2", "h3", "strong"):
        text = _clean_text(parsed.select_one(selector))
        if text:
            return text
    return None


def _title_parts(title: str | None) -> tuple[str | None, str | None]:
    if not title:
        return None, None
    match = re.match(r"^【(?P<type>[^】]+)】(?P<title>.+)$", title.strip())
    if not match:
        return None, title.strip()
    return match.group("type").strip() or None, match.group("title").strip() or title.strip()


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"\d{4}-\d{1,2}-\d{1,2}", value)
    if not match:
        return value.strip() or None
    year, month, day = match.group(0).split("-")
    return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"


def _normalize_key(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]+", "_", value.strip()).strip("_").casefold()


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


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")
