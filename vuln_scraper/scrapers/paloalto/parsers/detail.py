from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from bs4 import Tag

from vuln_scraper.scrapers.paloalto.config import BASE_URL
from vuln_scraper.scrapers.paloalto.parsers.common import (
    clean_multiline,
    clean_text,
    cve_ids_from_text,
    iso_date,
    soup,
    unique_links,
)


SECTION_KEYS = {
    "description": "description",
    "product status": "product_status",
    "required configuration for exposure": "required_configuration",
    "severity": "severity_detail",
    "exploitation status": "exploitation_status",
    "weakness type and impact": "weakness_type_and_impact",
    "solution": "solution",
    "workarounds and mitigations": "workarounds",
    "acknowledgments": "acknowledgments",
    "timeline": "timeline",
}
CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[A-Za-z0-9:/]+")


@dataclass(slots=True)
class PaloAltoDetailRecord:
    advisory_id: str | None = None
    title: str | None = None
    severity: str | None = None
    urgency: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_date: str | None = None
    updated_date: str | None = None
    discovered: str | None = None
    description: str | None = None
    products: list[str] = field(default_factory=list)
    product_status: list[dict[str, str | None]] = field(default_factory=list)
    required_configuration: str | None = None
    exploitation_status: str | None = None
    weakness: list[dict[str, str | None]] = field(default_factory=list)
    impact: list[dict[str, str | None]] = field(default_factory=list)
    solution: str | None = None
    workarounds: str | None = None
    acknowledgments: str | None = None
    timeline: list[dict[str, str | None]] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> PaloAltoDetailRecord:
    parsed = soup(html)
    title_text = clean_text(parsed.select_one("#content h2") or parsed.select_one("h2"))
    advisory_id, title = _split_title(title_text)
    sections = _sections(parsed.select_one("#content"))
    all_text = "\n".join((title_text, *sections.values()))

    return PaloAltoDetailRecord(
        advisory_id=advisory_id,
        title=title,
        severity=_severity(parsed, sections.get("severity_detail")),
        urgency=_urgency(parsed),
        cvss_score=_cvss_score(parsed),
        cvss_vector=_cvss_vector(parsed),
        published_date=_dated_summary_value(parsed, "Published"),
        updated_date=_dated_summary_value(parsed, "Updated"),
        discovered=_summary_value(parsed, "Discovered"),
        description=sections.get("description") or None,
        products=_products(parsed),
        product_status=_product_status(parsed),
        required_configuration=sections.get("required_configuration") or None,
        exploitation_status=sections.get("exploitation_status") or None,
        weakness=_linked_taxonomy(parsed, "cwe.mitre.org"),
        impact=_linked_taxonomy(parsed, "capec.mitre.org"),
        solution=sections.get("solution") or None,
        workarounds=sections.get("workarounds") or None,
        acknowledgments=sections.get("acknowledgments") or None,
        timeline=_timeline(parsed),
        cve_ids=cve_ids_from_text(all_text),
        reference_links=_reference_links(parsed),
        raw_sections=sections,
    )


def _split_title(title: str) -> tuple[str | None, str | None]:
    if not title:
        return None, None
    parts = title.split(" ", 1)
    if len(parts) == 2 and (parts[0].startswith("CVE-") or parts[0].startswith("PAN-SA-")):
        return parts[0], parts[1].strip() or None
    return None, title


def _sections(container: Tag | None) -> dict[str, str]:
    if container is None:
        return {}
    sections: dict[str, str] = {}
    for heading in container.find_all("h3"):
        heading_text = clean_text(heading)
        key = _section_key(heading_text)
        if key is None:
            continue
        nodes: list[Tag] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name == "h3":
                    break
                if clean_multiline(sibling):
                    nodes.append(sibling)
        text = "\n".join(clean_multiline(node) for node in nodes if clean_multiline(node)).strip()
        if text:
            sections[key] = text
    return sections


def _section_key(value: str) -> str | None:
    normalized = re.sub(r"\s+", " ", value).strip().casefold()
    if normalized.startswith("severity:"):
        return "severity_detail"
    return SECTION_KEYS.get(normalized)


def _severity(parsed, fallback: str | None) -> str | None:
    meta = parsed.find("meta", attrs={"name": "twitter:data1"})
    if meta and meta.get("content"):
        return str(meta["content"]).strip().upper()
    text = fallback or clean_text(parsed.select_one(".sa_cvss .CVSS"))
    for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        if value in text.upper().split():
            return value
    return None


def _urgency(parsed) -> str | None:
    urgency = parsed.select_one(".sa_cvss .CVSS span")
    text = clean_text(urgency)
    if text.upper().startswith("URGENCY "):
        return text.split(" ", 1)[1].strip().upper()
    return None


def _cvss_score(parsed) -> float | None:
    cvss = clean_text(parsed.select_one(".sa_cvss a.CVSS"))
    match = re.search(r"\d+(?:\.\d+)?", cvss)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _cvss_vector(parsed) -> str | None:
    link = parsed.select_one(".sa_cvss a[href*='CVSS:']")
    haystack = " ".join(
        str(value)
        for value in (
            link.get("href") if link else None,
            link.get("title") if link else None,
            clean_text(link),
        )
        if value
    )
    match = CVSS_VECTOR_RE.search(haystack)
    return match.group(0) if match else None


def _dated_summary_value(parsed, label: str) -> str | None:
    value_node = _summary_value_node(parsed, label)
    dated = value_node.select_one("[data-date]") if isinstance(value_node, Tag) else None
    return iso_date(dated.get("data-date") if dated else clean_text(value_node))


def _summary_value(parsed, label: str) -> str | None:
    text = clean_text(_summary_value_node(parsed, label))
    return text or None


def _summary_value_node(parsed, label: str):
    for small in parsed.select(".sa_links small"):
        if clean_text(small).casefold() == label.casefold():
            parent = small.parent
            return parent.find("b") if parent else None
    return None


def _products(parsed) -> list[str]:
    products: list[str] = []
    for row in _product_status_table(parsed).select("tr")[1:]:
        cells = row.find_all(["td", "th"], recursive=False)
        if cells and clean_text(cells[0]) and clean_text(cells[0]) not in products:
            products.append(clean_text(cells[0]))
    return products


def _product_status(parsed) -> list[dict[str, str | None]]:
    table = _product_status_table(parsed)
    rows: list[dict[str, str | None]] = []
    for row in table.select("tr")[1:]:
        cells = row.find_all(["td", "th"], recursive=False)
        if len(cells) >= 3:
            rows.append(
                {
                    "version": clean_text(cells[0]) or None,
                    "affected": clean_multiline(cells[1]) or None,
                    "unaffected": clean_multiline(cells[2]) or None,
                }
            )
    return rows


def _product_status_table(parsed):
    heading = parsed.find("h3", string=lambda value: value and clean_text(value).casefold() == "product status")
    siblings = heading.next_siblings if heading else []
    for sibling in siblings:
        if isinstance(sibling, Tag):
            if sibling.name == "h3":
                break
            table = sibling if sibling.name == "table" else sibling.find("table")
            if table:
                return table
    return soup("<table></table>").table


def _linked_taxonomy(parsed, domain_fragment: str) -> list[dict[str, str | None]]:
    items: list[dict[str, str | None]] = []
    for link in parsed.select(f'a[href*="{domain_fragment}"]'):
        text = clean_text(link)
        code = text.split(" ", 1)[0] if text else None
        item = {"id": code, "name": text, "url": link.get("href")}
        if item not in items:
            items.append(item)
    return items


def _timeline(parsed) -> list[dict[str, str | None]]:
    items: list[dict[str, str | None]] = []
    for item in parsed.select(".timeline > div"):
        dated = item.select_one("[data-date]")
        text = clean_text(item.select_one(".t"))
        items.append({"date": iso_date(dated.get("data-date") if dated else None), "text": text or None})
    return items


def _reference_links(parsed) -> list[str]:
    links = unique_links(parsed.select("#content a[href]"), base_url=BASE_URL)
    return [link for link in links if not link.endswith("#")]
