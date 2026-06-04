from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.avd.config import BASE_URL
from vuln_scraper.models import DetailRecord


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
SECTION_LABELS = (
    "影响范围",
    "安全版本",
    "解决建议",
    "参考链接",
    "CWE-ID",
    "受影响软件情况",
    "受影响软件",
)

METRIC_KEYS = (
    ("攻击路径", "attack_path"),
    ("攻击向量", "attack_path"),
    ("攻击复杂度", "attack_complexity"),
    ("权限要求", "privileges_required"),
    ("所需权限", "privileges_required"),
    ("影响范围", "scope"),
    ("作用域", "scope"),
    ("利用情况", "exp_maturity"),
    ("漏洞利用成熟度", "exp_maturity"),
    ("补丁情况", "patch_status"),
    ("机密性", "confidentiality"),
    ("保密性", "confidentiality"),
    ("完整性", "integrity"),
    ("可用性", "availability"),
    ("披露时间", "disclosure_date"),
)


def parse_detail_page(html: str) -> DetailRecord:
    soup = BeautifulSoup(html, "lxml")
    title = _extract_title(soup)
    text_detail = _extract_text_detail(soup)
    all_text = _clean_text(soup)
    attack_metrics = _extract_metrics(soup)

    return DetailRecord(
        cve_id=_extract_cve_id(title, all_text, attack_metrics),
        danger_level=_extract_danger_level(soup),
        exploitability=attack_metrics.get("exp_maturity"),
        patch_status=attack_metrics.get("patch_status"),
        description=_extract_description(text_detail),
        impact_range=_extract_section_lines(soup, text_detail, "影响范围", ("安全版本", "解决建议")),
        security_versions=_extract_section_lines(soup, text_detail, "安全版本", ("解决建议", "参考链接")),
        solution=_extract_section_text(soup, text_detail, "解决建议", ("参考链接", "CWE-ID", "受影响软件情况")),
        reference_links=_extract_reference_links(soup),
        cwe=_extract_cwe_table(soup),
        attack_metrics=attack_metrics,
        affected_software=_extract_affected_software(soup),
    )


def _extract_title(soup: BeautifulSoup) -> str | None:
    title = soup.select_one("span.header__title__text")
    if title:
        return _clean_text(title)

    for selector in ("h1", "h2", ".header__title"):
        node = soup.select_one(selector)
        if node:
            text = _clean_text(node)
            if text:
                return text
    return None


def _extract_danger_level(soup: BeautifulSoup) -> str | None:
    for selector in ("span.badge.btn-primary", ".badge.btn-primary", ".badge"):
        for badge in soup.select(selector):
            text = _clean_text(badge)
            if text in {"严重", "高危", "中危", "低危"} or "危" in text:
                return text
    return None


def _extract_text_detail(soup: BeautifulSoup) -> str:
    detail = soup.select_one("div.text-detail")
    if detail:
        return _clean_text_multiline(detail)
    return _clean_text_multiline(soup)


def _extract_description(text_detail: str) -> str | None:
    if not text_detail:
        return None

    first_stop = len(text_detail)
    for label in SECTION_LABELS:
        index = text_detail.find(label)
        if index >= 0:
            first_stop = min(first_stop, index)

    description = text_detail[:first_stop].strip()
    return description or None


def _extract_section_lines(
    soup: BeautifulSoup,
    text_detail: str,
    label: str,
    stop_labels: Iterable[str],
) -> list[str]:
    text = _extract_section_text(soup, text_detail, label, stop_labels)
    if not text:
        return []
    return _split_section_lines(text)


def _extract_section_text(
    soup: BeautifulSoup,
    text_detail: str,
    label: str,
    stop_labels: Iterable[str],
) -> str | None:
    from_text = _slice_between_labels(text_detail, label, stop_labels)
    if from_text:
        return from_text

    heading = _find_heading(soup, label)
    if not heading:
        return None

    chunks: list[str] = []
    for sibling in heading.find_next_siblings():
        sibling_text = _clean_text_multiline(sibling)
        if not sibling_text:
            continue
        if _starts_with_any_label(sibling_text, SECTION_LABELS):
            break
        chunks.append(sibling_text)

    text = "\n".join(chunks).strip()
    return text or None


def _slice_between_labels(text: str, label: str, stop_labels: Iterable[str]) -> str | None:
    start = text.find(label)
    if start < 0:
        return None

    start += len(label)
    stop = len(text)
    for stop_label in stop_labels:
        stop_index = text.find(stop_label, start)
        if stop_index >= 0:
            stop = min(stop, stop_index)

    section = text[start:stop].strip(" \n:：")
    return section or None


def _extract_reference_links(soup: BeautifulSoup) -> list[str]:
    links: list[str] = []
    selectors = [
        "table.table-sm a[href]",
        "table.table.table-sm a[href]",
        "table.table-responsive a[href]",
    ]

    for selector in selectors:
        for link in soup.select(selector):
            _append_link(links, link.get("href"))

    heading = _find_heading(soup, "参考链接")
    if heading:
        for sibling in heading.find_next_siblings():
            text = _clean_text(sibling)
            if text and _starts_with_any_label(text, SECTION_LABELS):
                break
            for link in sibling.find_all("a", href=True):
                _append_link(links, link.get("href"))

    if not links:
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            if href and href.startswith(("http://", "https://")):
                _append_link(links, href)

    return links


def _extract_metrics(soup: BeautifulSoup) -> dict[str, str]:
    metrics: dict[str, str] = {}

    for metric in soup.select("div.metric"):
        label_node = metric.select_one("p.metric-label, .metric-label")
        value_node = metric.select_one("div.metric-value, .metric-value")
        label = _normalize_label(_clean_text(label_node)) if label_node else ""
        value = _clean_text(value_node) if value_node else ""
        _store_metric(metrics, label, value)

    for row in soup.select("tr"):
        cells = [_clean_text(cell) for cell in row.find_all(["th", "td"])]
        if len(cells) == 2:
            _store_metric(metrics, cells[0], cells[1])
        elif len(cells) >= 4:
            for index in range(0, len(cells) - 1, 2):
                _store_metric(metrics, cells[index], cells[index + 1])

    return metrics


def _store_metric(metrics: dict[str, str], label: str, value: str) -> None:
    label = _normalize_label(label)
    value = _clean_scalar(value)
    if not label or not value:
        return

    for keyword, key in METRIC_KEYS:
        if keyword in label and key not in metrics:
            metrics[key] = value
            return


def _extract_cve_id(
    title: str | None,
    all_text: str,
    attack_metrics: dict[str, str],
) -> str | None:
    for value in (title, attack_metrics.get("cve_id"), all_text):
        if not value:
            continue
        match = CVE_RE.search(value)
        if match:
            return match.group(0).upper()
    return None


def _extract_cwe_table(soup: BeautifulSoup) -> list[dict[str, str | None]]:
    entries: list[dict[str, str | None]] = []

    for table in soup.find_all("table"):
        table_text = _clean_text(table)
        if "CWE" not in table_text:
            continue

        for row in table.find_all("tr"):
            cells = [_clean_text(cell) for cell in row.find_all(["td", "th"])]
            if not cells:
                continue

            joined = " ".join(cells)
            match = CWE_RE.search(joined)
            if not match:
                continue

            cwe_id = match.group(0).upper()
            name = next(
                (
                    cell
                    for cell in cells
                    if cell and cwe_id not in cell.upper() and "CWE-ID" not in cell.upper()
                ),
                None,
            )
            entry = {"id": cwe_id, "name": name}
            if entry not in entries:
                entries.append(entry)

    return entries


def _extract_affected_software(soup: BeautifulSoup) -> list[dict[str, str | None]]:
    software: list[dict[str, str | None]] = []

    for table in soup.find_all("table"):
        headers = _table_headers(table)
        table_text = _clean_text(table)
        context = " ".join([_nearby_heading_text(table), " ".join(headers), table_text[:200]])
        if _looks_like_cwe_table(table_text, headers) or _looks_like_reference_table(table_text, headers):
            continue
        if not _looks_like_software_table(context, headers):
            continue

        for record in _parse_software_rows(table, headers):
            if record not in software:
                software.append(record)

    return software


def _parse_software_rows(table: Tag, headers: list[str]) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = []
    rows = table.select("tbody tr") or table.find_all("tr")
    header_keys = [_header_to_key(header) for header in headers]

    for row in rows:
        cells = [_clean_text(cell) for cell in row.find_all("td")]
        if not cells:
            continue
        if headers and cells == headers:
            continue

        record = {"vendor": None, "product": None, "version": None, "impact": None}
        avd_table_record = _parse_avd_software_row(headers, cells)
        if avd_table_record:
            record = avd_table_record
        elif header_keys and len(header_keys) <= len(cells):
            for key, value in zip(header_keys, cells, strict=False):
                if key and value:
                    record[key] = value
        elif len(cells) >= 3:
            record["vendor"] = cells[0]
            record["product"] = cells[1]
            record["version"] = cells[2]
            if len(cells) >= 4:
                record["impact"] = cells[3]
        else:
            _merge_key_value_cells(record, cells)

        if any(record.values()) and record not in records:
            records.append(record)

    return records


def _parse_avd_software_row(
    headers: list[str],
    cells: list[str],
) -> dict[str, str | None] | None:
    joined_headers = " ".join(headers)
    if not all(token in joined_headers for token in ("类型", "厂商", "产品", "版本")):
        return None
    if len(cells) < 4 or "厂商" in cells:
        return None

    offset = 1 if cells[0].isdigit() else 0
    if len(cells) < offset + 4:
        return None

    impact_cells = cells[offset + 4 :]
    return {
        "vendor": cells[offset + 1] if len(cells) > offset + 1 else None,
        "product": cells[offset + 2] if len(cells) > offset + 2 else None,
        "version": cells[offset + 3] if len(cells) > offset + 3 else None,
        "impact": _clean_scalar(" ".join(impact_cells)) or None,
    }


def _merge_key_value_cells(record: dict[str, str | None], cells: list[str]) -> None:
    for index in range(0, len(cells) - 1, 2):
        key = _header_to_key(cells[index])
        if key and cells[index + 1]:
            record[key] = cells[index + 1]


def _table_headers(table: Tag) -> list[str]:
    first_row = table.find("tr")
    if not first_row:
        return []

    headers = [_clean_text(cell) for cell in first_row.find_all("th")]
    if headers:
        return headers

    cell_headers = [_clean_text(cell) for cell in first_row.find_all("td")]
    if cell_headers and any(_header_to_key(header) for header in cell_headers):
        return cell_headers
    if cell_headers and all(cell.find(["strong", "b"]) for cell in first_row.find_all("td")):
        return cell_headers
    return []


def _header_to_key(header: str) -> str | None:
    header = _normalize_label(header)
    if any(token in header for token in ("厂商", "供应商", "VENDOR")):
        return "vendor"
    if any(token in header for token in ("产品", "软件", "应用", "PRODUCT")):
        return "product"
    if any(token in header for token in ("版本", "VERSION")):
        return "version"
    if any(token in header for token in ("影响", "IMPACT")):
        return "impact"
    return None


def _looks_like_software_table(context: str, headers: list[str]) -> bool:
    header_text = " ".join(headers)
    if "受影响软件" in context:
        return True
    return bool(
        any(token in header_text for token in ("厂商", "供应商", "产品", "软件", "应用"))
        and any(token in header_text for token in ("版本", "影响"))
    )


def _looks_like_cwe_table(table_text: str, headers: list[str]) -> bool:
    header_text = " ".join(headers)
    return "CWE-ID" in table_text or ("CWE" in table_text and "漏洞类型" in table_text) or "CWE" in header_text


def _looks_like_reference_table(table_text: str, headers: list[str]) -> bool:
    header_text = " ".join(headers)
    return "参考链接" in header_text or table_text.startswith("参考链接 ")


def _nearby_heading_text(table: Tag) -> str:
    chunks: list[str] = []
    for previous in table.find_all_previous(["h1", "h2", "h3", "h4", "h5", "h6", "div"], limit=8):
        text = _clean_text(previous)
        if text and (previous.name != "div" or len(text) <= 80):
            chunks.append(text)
    return " ".join(chunks)


def _find_heading(soup: BeautifulSoup, label: str) -> Tag | None:
    for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "div", "p", "span"]):
        text = _clean_text(tag)
        if text == label or text.startswith(f"{label} "):
            return tag
    return None


def _split_section_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in re.split(r"[\n\r]+", text):
        line = _clean_scalar(line)
        if line and line not in SECTION_LABELS and line not in lines:
            lines.append(line)
    if len(lines) <= 1 and "；" in text:
        return [_clean_scalar(item) for item in text.split("；") if _clean_scalar(item)]
    return lines


def _append_link(links: list[str], href: str | None) -> None:
    if not href or href.startswith(("javascript:", "#")):
        return
    normalized = urljoin(BASE_URL, href)
    if normalized not in links:
        links.append(normalized)


def _starts_with_any_label(text: str, labels: Iterable[str]) -> bool:
    return any(text == label or text.startswith(label) for label in labels)


def _normalize_label(text: str) -> str:
    return _clean_scalar(text).rstrip(":：").upper()


def _clean_scalar(text: str) -> str:
    return " ".join(text.split()).strip()


def _clean_text(node) -> str:
    if node is None:
        return ""
    return _clean_scalar(node.get_text(" ", strip=True))


def _clean_text_multiline(node) -> str:
    if node is None:
        return ""
    text = node if isinstance(node, str) else node.get_text("\n", strip=True)
    lines = [_clean_scalar(line) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)
