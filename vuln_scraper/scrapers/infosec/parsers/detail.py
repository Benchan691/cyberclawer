from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from vuln_scraper.scrapers.govcert.parsers.detail import parse_detail_page as parse_govcert_detail_page


@dataclass(slots=True)
class InfoSecDetailRecord:
    alert_code: str | None = None
    alert_type: str | None = None
    published_date: str | None = None
    summary: str | None = None
    description: str | None = None
    affected_systems: list[str] = field(default_factory=list)
    impact: str | None = None
    recommendation: str | None = None
    more_information_links: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)
    govcert_detail_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> InfoSecDetailRecord:
    govcert = parse_govcert_detail_page(html).to_dict()
    return InfoSecDetailRecord(
        alert_code=govcert.get("alert_code"),
        alert_type=govcert.get("alert_type"),
        published_date=govcert.get("published_date"),
        description=govcert.get("description"),
        affected_systems=list(govcert.get("affected_systems") or []),
        impact=govcert.get("impact"),
        recommendation=govcert.get("recommendation"),
        more_information_links=list(govcert.get("more_information_links") or []),
        tags=list(govcert.get("tags") or []),
        cve_ids=list(govcert.get("cve_ids") or []),
        raw_sections=dict(govcert.get("raw_sections") or {}),
    )
