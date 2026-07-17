from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from bs4 import Tag

from vuln_scraper.scrapers.govcert.config import BASE_URL
from vuln_scraper.scrapers.govcert.parsers.common import (
    clean_multiline,
    clean_text,
    cve_ids_from_text,
    normalize_date,
    parse_alert_title,
    soup,
    unique_links,
)


SECTION_KEYS = {
    "description": "description",
    "affected systems": "affected_systems",
    "impact": "impact",
    "recommendation": "recommendation",
    "more information": "more_information",
}
URL_RE = re.compile(r"https?://[^\s<>\"]+")


@dataclass(slots=True)
class GovCERTDetailRecord:
    alert_code: str | None = None
    alert_type: str | None = None
    published_date: str | None = None
    description: str | None = None
    affected_systems: list[str] = field(default_factory=list)
    impact: str | None = None
    recommendation: str | None = None
    more_information_links: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> GovCERTDetailRecord:
    parsed = soup(html)
    title = clean_text(parsed.select_one("#doc_title"))
    alert_code, alert_type, _ = parse_alert_title(title)
    sections = _sections(parsed.select_one(".noneditable"))
    published_date = _published_date(parsed)
    more_information = sections.get("more_information", "")
    full_text = "\n".join((title, published_date or "", *sections.values()))

    return GovCERTDetailRecord(
        alert_code=alert_code,
        alert_type=alert_type,
        published_date=published_date,
        description=sections.get("description") or None,
        affected_systems=_lines(sections.get("affected_systems")),
        impact=sections.get("impact") or None,
        recommendation=sections.get("recommendation") or None,
        more_information_links=_more_information_links(parsed, more_information),
        tags=_tags(parsed),
        cve_ids=cve_ids_from_text(full_text),
        raw_sections=sections,
    )


def _published_date(parsed) -> str | None:
    for paragraph in parsed.select("p.text-content"):
        text = clean_text(paragraph)
        if text.casefold().startswith("published on:"):
            return normalize_date(text.split(":", 1)[1].strip())
    return None


def _sections(container: Tag | None) -> dict[str, str]:
    if container is None:
        return {}

    sections: dict[str, str] = {}
    for heading in container.find_all(("h2", "h4")):
        label = clean_text(heading).rstrip(":").casefold()
        key = SECTION_KEYS.get(label)
        if key is None:
            continue

        nodes: list[Tag] = []
        for sibling in heading.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.name in {"h2", "h4"}:
                    break
                if clean_multiline(sibling):
                    nodes.append(sibling)
        text = "\n".join(clean_multiline(node) for node in nodes if clean_multiline(node)).strip()
        if text:
            sections[key] = text
    return sections


def _lines(value: str | None) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _more_information_links(parsed, section_text: str) -> list[str]:
    container = parsed.select_one(".noneditable")
    links = unique_links(container.find_all("a", href=True) if container else [], base_url=BASE_URL)

    for match in URL_RE.findall(section_text):
        url = match.rstrip(").,;")
        if url not in links:
            links.append(url)
    return links


def _tags(parsed) -> list[str]:
    tag_box = parsed.find("strong", string=lambda value: value and "Tag:" in value)
    if tag_box is None:
        return []

    tags: list[str] = []
    parent = tag_box.parent
    for link in parent.find_all("a") if parent else []:
        tag = clean_text(link)
        if tag and tag not in tags:
            tags.append(tag)
    return tags
