from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.qianxin.config import BASE_URL


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"]+")
TITLE_STATUS_RE = re.compile(r"^【(?P<status>[^】]+)】(?P<title>.+)$")


@dataclass(slots=True)
class QianxinDetailRecord:
    article_id: str | None = None
    title: str | None = None
    threat_status: str | None = None
    category: str | None = None
    level: str | None = None
    author: str | None = None
    digest: str | None = None
    cover_url: str | None = None
    read_num: int | None = None
    published_at: str | None = None
    published_date: str | None = None
    updated_at: str | None = None
    updated_date: str | None = None
    vuln_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    description: str | None = None
    raw_sections: dict[str, str] = field(default_factory=dict)
    reference_links: list[str] = field(default_factory=list)
    prev_article: dict[str, Any] | None = None
    next_article: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_article_detail(data: Any) -> QianxinDetailRecord:
    payload = _coerce_json(data)
    item = _detail_payload(payload)
    content = _optional_str(item.get("content")) or ""
    parsed = BeautifulSoup(content, "lxml")
    body_text = _clean_multiline(parsed)
    raw_title = _optional_str(item.get("title"))
    threat_status, clean_title = _title_parts(raw_title)
    text_for_ids = "\n".join(value for value in (raw_title, item.get("digest"), body_text) if isinstance(value, str))
    publish_time = _optional_str(item.get("publish_time"))
    update_time = _optional_str(item.get("update_time"))

    return QianxinDetailRecord(
        article_id=_optional_str(item.get("id")),
        title=clean_title,
        threat_status=threat_status,
        category=_optional_str(item.get("category")),
        level=_optional_str(item.get("level")),
        author=_optional_str(item.get("author")),
        digest=_clean_text(item.get("digest")),
        cover_url=_optional_str(item.get("cover")),
        read_num=_optional_int(item.get("read_num")),
        published_at=publish_time,
        published_date=_iso_date(publish_time),
        updated_at=update_time,
        updated_date=_iso_date(update_time),
        vuln_ids=_split_ids(item.get("vuln_ids")),
        cve_ids=_cve_ids(text_for_ids),
        description=body_text or None,
        raw_sections=_sections(parsed),
        reference_links=_reference_links(parsed, body_text),
        prev_article=_article_ref(item.get("prev")),
        next_article=_article_ref(item.get("next")),
        raw={key: value for key, value in item.items() if key != "content"},
    )


def _detail_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict):
            return dict(data)
        if payload.get("id") or payload.get("content"):
            return dict(payload)
    raise ValueError("Qianxin detail response did not contain an article object")


def _sections(parsed: BeautifulSoup) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current_key: str | None = None
    for node in parsed.find_all(["h1", "h2", "h3", "h4", "p"]):
        text = _clean_text(node)
        if not text:
            continue
        if node.name in {"h1", "h2", "h3", "h4"} or _looks_like_heading(text):
            current_key = _normalize_key(text)
            sections.setdefault(current_key, [])
            continue
        if current_key:
            sections[current_key].append(text)
    return {key: "\n".join(value).strip() for key, value in sections.items() if any(value)}


def _looks_like_heading(text: str) -> bool:
    return bool(re.match(r"^(?:第[一二三四五六七八九十0-9]+章|[一二三四五六七八九十0-9]+[、.．])\s*", text))


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


def _article_ref(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    article_id = _optional_str(value.get("id"))
    title = _optional_str(value.get("title"))
    if not article_id or article_id == "0":
        return None
    return {"id": article_id, "title": title}


def _title_parts(title: str | None) -> tuple[str | None, str | None]:
    if not title:
        return None, None
    match = TITLE_STATUS_RE.match(title.strip())
    if not match:
        return None, title.strip()
    return match.group("status").strip() or None, match.group("title").strip() or title.strip()


def _split_ids(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = _optional_str(value)
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,，;；\s]+", text) if part.strip()]


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


def _clean_text(node: object | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, Tag):
        text = node.get_text(" ", strip=True)
    else:
        text = str(node)
    text = " ".join(text.replace("\xa0", " ").split())
    return text or None


def _clean_multiline(node: object | None) -> str:
    if node is None:
        return ""
    if isinstance(node, Tag):
        text = node.get_text("\n", strip=True)
    else:
        text = str(node)
    lines = [" ".join(line.replace("\xa0", " ").split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
