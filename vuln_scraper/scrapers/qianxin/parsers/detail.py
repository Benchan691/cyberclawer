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
CHAPTER_RE = re.compile(r"^第([一二三四五六])章")
CHAPTER_NUMBERS = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6}
DESCRIPTION_KEYS = (
    "security_advisory",
    "vulnerability_information",
    "threat_assessment",
    "affected_assets",
    "recommendations",
    "references",
)
CHAPTER_TITLE_PATTERNS: list[tuple[str, str]] = [
    ("受影响资产", "affected_assets"),
    ("处置建议", "recommendations"),
    ("参考资料", "references"),
    ("安全通告", "security_advisory"),
    ("漏洞信息", "vulnerability_information"),
    ("漏洞概述", "vulnerability_information"),
    ("威胁评估", "threat_assessment"),
]
NUMERIC_CHAPTER_KEYS = {
    1: "security_advisory",
    2: "vulnerability_information",
    3: "threat_assessment",
    4: "affected_assets",
    5: "recommendations",
    6: "references",
}


def _empty_description() -> dict[str, Any]:
    return {
        "security_advisory": "",
        "vulnerability_information": {},
        "threat_assessment": {},
        "affected_assets": "",
        "recommendations": [],
        "references": [],
    }


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
    description: dict[str, Any] = field(default_factory=_empty_description)
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
    chapters = _chapter_nodes(parsed)
    description = _parse_description(chapters)
    body_text = _chapters_text(chapters)
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
        description=description,
        reference_links=_reference_links(chapters, body_text),
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


def _chapter_nodes(parsed: BeautifulSoup) -> dict[str, list[Tag]]:
    chapters = {key: [] for key in DESCRIPTION_KEYS}
    root = parsed.select_one("#poc-preview") or parsed
    first_heading = root.find(
        lambda node: isinstance(node, Tag)
        and node.name in {"h1", "h2", "h3", "h4"}
        and _chapter_key(_clean_text(node)) == "security_advisory"
    )
    if not isinstance(first_heading, Tag):
        return chapters

    current: str | None = None
    for node in first_heading.parent.children:
        if not isinstance(node, Tag):
            continue
        chapter_key = _chapter_key(_clean_text(node))
        if chapter_key is not None:
            current = chapter_key
            continue
        if current is None:
            continue
        if _compact_text(_clean_text(node)) == "奇安信CERT":
            break
        chapters[current].append(node)
    return chapters


def _chapter_key(text: str | None) -> str | None:
    compact = _compact_text(text)
    match = CHAPTER_RE.match(compact)
    if not match:
        return None
    title_part = compact[match.end() :]
    for keyword, key in CHAPTER_TITLE_PATTERNS:
        if keyword in title_part or keyword in compact:
            return key
    number = CHAPTER_NUMBERS.get(match.group(1))
    if number is not None:
        return NUMERIC_CHAPTER_KEYS.get(number)
    return None


def _parse_description(chapters: dict[str, list[Tag]]) -> dict[str, Any]:
    return {
        "security_advisory": _chapter_text(chapters["security_advisory"]),
        "vulnerability_information": _parse_vulnerability_information(
            chapters["vulnerability_information"]
        ),
        "threat_assessment": _parse_threat_assessment(chapters["threat_assessment"]),
        "affected_assets": _chapter_text(chapters["affected_assets"]),
        "recommendations": _chapter_lines(chapters["recommendations"]),
        "references": _chapter_lines(chapters["references"]),
    }


def normalize_qianxin_detail(detail: dict[str, Any]) -> dict[str, Any]:
    raw = detail.get("raw")
    if not isinstance(raw, dict) or not raw.get("content"):
        return dict(detail)
    item = dict(raw)
    if detail.get("article_id") and not item.get("id"):
        item["id"] = detail["article_id"]
    for key in ("title", "author", "cover", "category", "digest", "read_num", "publish_time", "update_time"):
        if detail.get(key) is not None and item.get(key) in (None, ""):
            mapped = {
                "cover_url": "cover",
                "published_at": "publish_time",
                "updated_at": "update_time",
            }.get(key, key)
            item[mapped] = detail[key]
    return parse_article_detail(item).to_dict()


def _parse_vulnerability_information(nodes: list[Tag]) -> dict[str, Any]:
    table, before, after = _split_around_table(nodes)
    result: dict[str, Any] = {}
    summary = _chapter_text(before)
    reproduction = _chapter_text(after)
    if summary:
        result["summary"] = summary
    if table is not None:
        result.update(
            _table_pairs(
                table,
                {
                    "漏洞名称": "vulnerability_name",
                    "公开时间": "published_date",
                    "更新时间": "updated_date",
                    "CVE编号": "cve_id",
                    "其他编号": "other_id",
                    "威胁类型": "threat_type",
                    "技术类型": "technical_type",
                    "厂商": "vendor",
                    "产品": "product",
                    "漏洞描述": "vulnerability_description",
                    "影响版本": "affected_versions",
                    "其他受影响组件": "other_affected_components",
                },
                list_fields={"affected_versions"},
            )
        )
        risk = _table_group(
            table,
            "风险等级",
            {
                "奇安信CERT风险评级": "qianxin_cert_rating",
                "风险等级": "risk_level",
            },
        )
        if risk:
            result["risk"] = risk
        threat_status = _table_group(
            table,
            "现时威胁状态",
            {
                "POC状态": "poc_status",
                "EXP状态": "exp_status",
                "在野利用状态": "in_the_wild_status",
                "技术细节状态": "technical_details_status",
            },
        )
        if threat_status:
            result["current_threat_status"] = threat_status
    if reproduction:
        result["reproduction"] = reproduction
    return result


def _parse_threat_assessment(nodes: list[Tag]) -> dict[str, Any]:
    table, before, after = _split_around_table(nodes)
    result: dict[str, Any] = {}
    context = _chapter_text([*before, *after])
    if context:
        result["context"] = context
    if table is None:
        return result

    result.update(
        _table_pairs(
            table,
            {
                "漏洞名称": "vulnerability_name",
                "CVE编号": "cve_id",
                "其他编号": "other_id",
                "CVSS3.1评级": "cvss_3_1_rating",
                "CVSS3.1分数": "cvss_3_1_score",
                "利用条件": "exploitation_conditions",
                "危害描述": "impact_description",
            },
            list_fields={"exploitation_conditions"},
        )
    )
    vector = _cvss_vector(table)
    if vector:
        result["cvss_vector"] = vector
    return result


def _split_around_table(nodes: list[Tag]) -> tuple[Tag | None, list[Tag], list[Tag]]:
    for index, node in enumerate(nodes):
        table = node if node.name == "table" else node.find("table")
        if isinstance(table, Tag):
            return table, nodes[:index], nodes[index + 1 :]
    return None, nodes, []


def _table_pairs(
    table: Tag,
    aliases: dict[str, str],
    *,
    list_fields: set[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    list_fields = list_fields or set()
    for cells in _table_rows(table):
        for index in range(0, len(cells) - 1, 2):
            key = aliases.get(_table_label(cells[index]))
            if not key:
                continue
            lines = _cell_lines(cells[index + 1])
            if key in list_fields:
                result[key] = lines
            elif lines:
                result[key] = _normalize_table_value(key, "\n".join(lines))
    return result


def _table_group(table: Tag, section: str, aliases: dict[str, str]) -> dict[str, str]:
    rows = _table_rows(table)
    for index, cells in enumerate(rows[:-2]):
        if not cells or _table_label(cells[0]) != section.upper():
            continue
        headers = rows[index + 1]
        values = rows[index + 2]
        result: dict[str, str] = {}
        for header, value in zip(headers, values, strict=False):
            key = aliases.get(_table_label(header))
            text = _normalize_table_value(key or "", _cell_text(value))
            if key and text:
                result[key] = text
        return result
    return {}


def _cvss_vector(table: Tag) -> dict[str, str]:
    aliases = {
        "访问途径（AV）": "attack_vector",
        "攻击复杂度（AC）": "attack_complexity",
        "用户认证（AU）": "authentication",
        "用户交互（UI）": "user_interaction",
        "影响范围（S）": "scope",
        "机密性影响（C）": "confidentiality_impact",
        "完整性影响（I）": "integrity_impact",
        "可用性影响（A）": "availability_impact",
    }
    rows = _table_rows(table)
    result: dict[str, str] = {}
    index = 0
    while index < len(rows) - 1:
        headers = rows[index]
        if not headers:
            index += 1
            continue
        labels = [_compact_text(_clean_text(cell)).upper() for cell in headers]
        if labels[0] == "CVSS向量":
            headers = headers[1:]
            labels = labels[1:]
        elif labels[0] in {"利用条件", "危害描述"}:
            break
        elif not any(label in aliases for label in labels):
            index += 1
            continue
        values = rows[index + 1]
        for label, value in zip(labels, values, strict=False):
            key = aliases.get(label)
            text = _normalize_table_value(key or "", _cell_text(value))
            if key and text:
                result[key] = text
        index += 2
    return result


def _table_rows(table: Tag) -> list[list[Tag]]:
    return [
        cells
        for row in table.find_all("tr")
        if (cells := row.find_all(["th", "td"], recursive=False))
    ]


def _cell_lines(cell: Tag) -> list[str]:
    paragraphs = cell.find_all(["p", "li"])
    if paragraphs:
        return [text for node in paragraphs if (text := _clean_text(node))]
    return [line for line in _clean_multiline(cell).splitlines() if line]


def _cell_text(cell: Tag) -> str:
    return "\n".join(_cell_lines(cell))


def _table_label(cell: Tag) -> str:
    return _compact_text(_clean_text(cell)).upper()


def _normalize_table_value(key: str, value: str) -> str:
    if key in {"published_date", "updated_date"}:
        value = re.sub(r"(?<=\d)\s+(?=\d)", "", value)
        value = re.sub(r"\s*-\s*", "-", value)
    if key in {"cve_id", "other_id"}:
        value = re.sub(r"\s+", "", value)
    value = re.sub(r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])", "", value)
    return value.strip()


def _chapter_text(nodes: list[Tag]) -> str:
    return "\n".join(_chapter_lines(nodes))


def _chapter_lines(nodes: list[Tag]) -> list[str]:
    lines: list[str] = []
    for node in nodes:
        if node.name == "table" or node.find("table"):
            continue
        if text := _clean_text(node):
            lines.append(text)
    return lines


def _chapters_text(chapters: dict[str, list[Tag]]) -> str:
    lines: list[str] = []
    for key in DESCRIPTION_KEYS:
        lines.extend(text for node in chapters[key] if (text := _clean_text(node)))
    return "\n".join(lines)


def _reference_links(chapters: dict[str, list[Tag]], text: str) -> list[str]:
    links: list[str] = []
    for nodes in chapters.values():
        for node in nodes:
            linked_nodes = [node] if node.name == "a" and node.get("href") else []
            for link in [*linked_nodes, *node.find_all("a", href=True)]:
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


def _compact_text(value: str | None) -> str:
    return re.sub(r"\s+", "", value or "")


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
