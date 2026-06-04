from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.hkcert.config import BASE_URL


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SECTION_LABELS = {
    "impact": "Impact",
    "systems_affected": "System / Technologies affected",
    "solutions": "Solutions",
    "vulnerability_identifiers": "Vulnerability Identifier",
    "bulletin_source": "Source",
    "related_links": "Related Link",
}


@dataclass(slots=True)
class HKCERTDetailRecord:
    intro: str | None = None
    note: str | None = None
    impact: str | None = None
    systems_affected: str | None = None
    solutions: str | None = None
    solution_links: list[str] = field(default_factory=list)
    vulnerability_identifiers: list[dict[str, str]] = field(default_factory=list)
    bulletin_source: str | None = None
    related_links: list[str] = field(default_factory=list)
    risk_level: str | None = None
    release_date: str | None = None
    last_update_date: str | None = None
    views: str | None = None
    summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> HKCERTDetailRecord:
    soup = BeautifulSoup(html, "lxml")
    sections = {key: _section_nodes(soup, label) for key, label in SECTION_LABELS.items()}
    release_date, last_update_date, views = _metadata(soup)

    return HKCERTDetailRecord(
        intro=_intro(soup),
        note=_note(soup),
        impact=_section_text(sections["impact"]),
        systems_affected=_section_text(sections["systems_affected"]),
        solutions=_section_text(sections["solutions"]),
        solution_links=_links_from_nodes(sections["solutions"]),
        vulnerability_identifiers=_vulnerability_identifiers(sections["vulnerability_identifiers"]),
        bulletin_source=_section_text(sections["bulletin_source"]),
        related_links=_links_from_nodes(sections["related_links"]),
        risk_level=_risk_level(soup),
        release_date=release_date,
        last_update_date=last_update_date,
        views=views,
        summary=_intro(soup),
    )


def _intro(soup: BeautifulSoup) -> str | None:
    intro = soup.select_one(".page-intro")
    text = _clean_multiline(intro)
    return text or None


def _note(soup: BeautifulSoup) -> str | None:
    for paragraph in soup.select(".page-intro p, .inner-context .ckec p"):
        text = _clean_text(paragraph)
        if text.startswith("Note:"):
            return text
    return None


def _section_nodes(soup: BeautifulSoup, label: str) -> list[Tag]:
    heading = next(
        (
            node
            for node in soup.find_all("h2")
            if _clean_text(node) == label
        ),
        None,
    )
    if heading is None:
        return []

    nodes: list[Tag] = []
    for sibling in heading.next_siblings:
        if isinstance(sibling, Tag) and sibling.name == "h2":
            break
        if isinstance(sibling, Tag) and sibling.name != "hr":
            nodes.append(sibling)
    return nodes


def _section_text(nodes: list[Tag]) -> str | None:
    text = "\n".join(_clean_multiline(node) for node in nodes if _clean_multiline(node)).strip()
    return text or None


def _vulnerability_identifiers(nodes: list[Tag]) -> list[dict[str, str]]:
    identifiers: list[dict[str, str]] = []
    for cve_id in CVE_RE.findall(_section_text(nodes) or ""):
        entry = {"cve_id": cve_id.upper()}
        if entry not in identifiers:
            identifiers.append(entry)
    return identifiers


def _links_from_nodes(nodes: list[Tag]) -> list[str]:
    links: list[str] = []
    for node in nodes:
        for link in node.find_all("a", href=True):
            href = urljoin(BASE_URL, link["href"])
            if href not in links:
                links.append(href)
    return links


def _risk_level(soup: BeautifulSoup) -> str | None:
    for selector in (".risk-meter__text", ".risk-meter .sr-only", ".sr-only"):
        node = soup.select_one(selector)
        text = _clean_text(node)
        if text:
            return text.removeprefix("RISK:").strip()
    return None


def _metadata(soup: BeautifulSoup) -> tuple[str | None, str | None, str | None]:
    text = _clean_text(soup.select_one(".page-date")) or _clean_text(soup.select_one(".listingcard__info"))
    release_date = _metadata_match(text, "Release Date")
    last_update_date = _metadata_match(text, "Last Update Date")
    views_match = re.search(r"(\d[\d,]*)\s+Views", text)
    views = views_match.group(1).replace(",", "") if views_match else None
    return release_date, last_update_date, views


def _metadata_match(text: str, label: str) -> str | None:
    match = re.search(
        rf"{re.escape(label)}:\s*(.+?)(?:\s+Last Update Date:|\s+Release Date:|\s+\d[\d,]*\s+Views|$)",
        text,
    )
    return match.group(1).strip() if match else None


def _clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).split())


def _clean_multiline(node) -> str:
    if node is None:
        return ""
    lines = [line.strip() for line in node.get_text("\n", strip=True).splitlines()]
    return "\n".join(line for line in lines if line and line != "\xa0")
