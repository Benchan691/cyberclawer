from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.cnvd.config import BASE_URL


CNVD_ID_RE = re.compile(r"CNVD-\d{4}-\d{4,}", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"]+")
CVSS_VECTOR_RE = re.compile(r"CVSS:\d(?:\.\d)?/[A-Z:0-9./-]+")
CVSS_SCORE_RE = re.compile(r"\b([0-9](?:\.[0-9])?|10(?:\.0)?)\b")
LABEL_RE = re.compile(r"[:：]\s*$")


@dataclass(slots=True)
class CNVDDetailRecord:
    cnvd_id: str | None = None
    title: str | None = None
    severity: str | None = None
    cvss_score: str | None = None
    cvss_vector: str | None = None
    affected_products: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    description: str | None = None
    solution: str | None = None
    reference_links: list[str] = field(default_factory=list)
    published_date: str | None = None
    updated_date: str | None = None
    raw_fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> CNVDDetailRecord:
    parsed = BeautifulSoup(html or "", "lxml")
    raw_fields = _raw_fields(parsed)
    all_text = _clean_multiline(parsed)

    return CNVDDetailRecord(
        cnvd_id=_first_cnvd_id(raw_fields, all_text),
        title=_title(parsed, raw_fields),
        severity=_field_value(raw_fields, ("危害级别", "危害等级", "综合评级", "漏洞级别")),
        cvss_score=_cvss_score(raw_fields),
        cvss_vector=_cvss_vector(raw_fields, all_text),
        affected_products=_split_lines(
            _field_value(raw_fields, ("影响产品", "影响范围", "受影响产品", "影响版本"))
        ),
        cve_ids=_cve_ids("\n".join((*raw_fields.values(), all_text))),
        description=_field_value(raw_fields, ("漏洞描述", "描述", "漏洞介绍")),
        solution=_field_value(raw_fields, ("漏洞解决方案", "解决方案", "修复建议", "处置建议")),
        reference_links=_reference_links(parsed, all_text),
        published_date=_field_value(raw_fields, ("公开日期", "发布时间", "发布日期", "收录时间")),
        updated_date=_field_value(raw_fields, ("更新时间", "更新日期", "最后更新时间")),
        raw_fields=raw_fields,
    )


def _raw_fields(parsed: BeautifulSoup) -> dict[str, str]:
    fields: dict[str, str] = {}
    for row in parsed.find_all("tr"):
        cells = [_clean_multiline(cell) for cell in row.find_all(["th", "td"])]
        cells = [cell for cell in cells if cell]
        if len(cells) == 2:
            _store_field(fields, cells[0], cells[1])
        elif len(cells) >= 4:
            for index in range(0, len(cells) - 1, 2):
                _store_field(fields, cells[index], cells[index + 1])

    for container in parsed.select("dl"):
        terms = container.find_all("dt")
        for term in terms:
            value_node = term.find_next_sibling("dd")
            if value_node is not None:
                _store_field(fields, _clean_text(term), _clean_multiline(value_node))

    for node in parsed.find_all(["li", "p", "div"]):
        text = _clean_multiline(node)
        if "\n" in text or ("：" not in text and ":" not in text):
            continue
        label, value = re.split(r"[:：]", text, maxsplit=1)
        if len(label) <= 16 and value.strip():
            _store_field(fields, label, value)

    return fields


def _store_field(fields: dict[str, str], label: str, value: str) -> None:
    key = _normalize_label(label)
    value = value.strip()
    if key and value and key not in fields:
        fields[key] = value


def _normalize_label(label: str) -> str:
    return LABEL_RE.sub("", _clean_text(label)).strip()


def _field_value(fields: dict[str, str], labels: tuple[str, ...]) -> str | None:
    for wanted in labels:
        for label, value in fields.items():
            if wanted == label or wanted in label:
                return value.strip() or None
    return None


def _first_cnvd_id(fields: dict[str, str], text: str) -> str | None:
    explicit = _field_value(fields, ("CNVD编号", "CNVD 编号", "编号"))
    for value in (explicit, text):
        if not value:
            continue
        match = CNVD_ID_RE.search(value)
        if match:
            return match.group(0).upper()
    return None


def _title(parsed: BeautifulSoup, fields: dict[str, str]) -> str | None:
    field_title = _field_value(fields, ("漏洞名称", "标题"))
    if field_title and field_title != "相关漏洞":
        return field_title
    for selector in ("h1", "h2", ".title", ".flaw-title", ".blkContainerSblk h1"):
        text = _clean_text(parsed.select_one(selector))
        if text and text != "相关漏洞" and "CNVD" not in text.upper():
            return text
    patch_title = _field_value(fields, ("厂商补丁",))
    if patch_title and patch_title.endswith("的补丁"):
        return patch_title.removesuffix("的补丁").strip() or None
    title_node = parsed.find("title")
    title = _clean_text(title_node)
    return title if title and title != "相关漏洞" else None


def _cvss_score(fields: dict[str, str]) -> str | None:
    value = _field_value(fields, ("CVSS", "危害级别", "综合评级"))
    if not value:
        return None
    match = CVSS_SCORE_RE.search(value)
    return match.group(1) if match else None


def _cvss_vector(fields: dict[str, str], text: str) -> str | None:
    for value in (*fields.values(), text):
        match = CVSS_VECTOR_RE.search(value)
        if match:
            return match.group(0)
    return None


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


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


def _split_lines(value: str | None) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[\n;；]+", value)
    return [part.strip() for part in parts if part.strip()]


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
