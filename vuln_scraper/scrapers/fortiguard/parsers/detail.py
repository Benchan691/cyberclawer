from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from vuln_scraper.scrapers.fortiguard.config import BASE_URL
from vuln_scraper.scrapers.fortiguard.parsers.common import (
    CVSS_VECTOR_RE,
    IR_CODE_RE,
    clean_text,
    cve_ids_from_text,
    iso_date,
    soup,
)


@dataclass(slots=True)
class FortiguardDetailRecord:
    advisory_id: str | None = None
    title: str | None = None
    summary: str | None = None
    severity: str | None = None
    component: str | None = None
    discovered: str | None = None
    attack_type: str | None = None
    known_exploited: str | None = None
    impact: str | None = None
    published_date: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    timeline: list[dict[str, str | None]] = field(default_factory=list)
    affected_products: list[dict[str, str | None]] = field(default_factory=list)
    cvrf_url: str | None = None
    csaf_url: str | None = None
    csaf: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> FortiguardDetailRecord:
    parsed = soup(html)
    meta = _meta_map(parsed)
    title = clean_text(parsed.select_one("h1.title")) or None
    summary = _section_paragraph(parsed, "Summary")
    advisory_id = _advisory_id(meta.get("IR Number"), title, html)
    cve_ids = _cve_ids(parsed, meta.get("CVE ID"), summary or "")
    cvss_score, cvss_vector = _cvss(parsed, meta.get("CVSSv3 Score"))
    cvrf_url, csaf_url = _download_urls(parsed)

    return FortiguardDetailRecord(
        advisory_id=advisory_id,
        title=title,
        summary=summary,
        severity=_severity(meta.get("Severity")),
        component=meta.get("Component"),
        discovered=meta.get("Discovered"),
        attack_type=meta.get("Attack Type"),
        known_exploited=meta.get("Known Exploited"),
        impact=meta.get("Impact"),
        published_date=iso_date(meta.get("Published Date")),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cve_ids=cve_ids,
        timeline=_timeline(parsed),
        affected_products=_affected_products(parsed),
        cvrf_url=cvrf_url,
        csaf_url=csaf_url,
        csaf=None,
    )


def _meta_map(parsed) -> dict[str, str]:
    values: dict[str, str] = {}
    for row in parsed.select("table.meta tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) < 2:
            continue
        key = clean_text(cells[0])
        value = clean_text(cells[1])
        if key:
            values[key] = value
    return values


def _advisory_id(*candidates: str | None) -> str | None:
    for candidate in candidates:
        if not candidate:
            continue
        match = IR_CODE_RE.search(candidate)
        if match:
            return match.group(0).upper()
    return None


def _section_paragraph(parsed, heading: str) -> str | None:
    for item in parsed.select("div.detail-item"):
        title = clean_text(item.select_one("h3"))
        if title.lower() != heading.lower():
            continue
        paragraphs = [clean_text(node) for node in item.select("p") if clean_text(node)]
        if paragraphs:
            return "\n".join(paragraphs)
        text = clean_text(item)
        prefix = heading
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix) :].strip()
        return text or None
    return None


def _cve_ids(parsed, meta_value: str | None, summary: str) -> list[str]:
    cves = [
        clean_text(node).upper()
        for node in parsed.select("button.cve-button[data-cveid], button.cve-button")
        if clean_text(node)
    ]
    if not cves and meta_value:
        cves = cve_ids_from_text(meta_value)
    if not cves:
        cves = cve_ids_from_text(summary)
    # preserve order / uniqueness
    seen: set[str] = set()
    ordered: list[str] = []
    for cve in cves:
        if cve not in seen:
            ordered.append(cve)
            seen.add(cve)
    return ordered


def _severity(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    match = re.search(r"(Critical|High|Medium|Low|Info)", text, re.IGNORECASE)
    return match.group(1).title() if match else text


def _cvss(parsed, meta_value: str | None) -> tuple[float | None, str | None]:
    score: float | None = None
    vector: str | None = None
    link = parsed.select_one("table.meta a[href*='cvss']")
    if link is not None:
        score_text = clean_text(link)
        href = link.get("href") or ""
        try:
            score = float(score_text)
        except ValueError:
            score = None
        vector_match = CVSS_VECTOR_RE.search(href.replace("&amp;", "&"))
        if vector_match:
            vector = vector_match.group(0)
        elif "vector=" in href:
            raw = href.split("vector=", 1)[-1].split("&", 1)[0].strip()
            if raw:
                vector = f"CVSS:3.1/{raw}" if not raw.upper().startswith("CVSS:") else raw
    if score is None and meta_value:
        match = re.search(r"(\d+(?:\.\d+)?)", meta_value)
        if match:
            score = float(match.group(1))
    return score, vector


def _download_urls(parsed) -> tuple[str | None, str | None]:
    cvrf_url: str | None = None
    csaf_url: str | None = None
    for link in parsed.select("table.meta a[href]"):
        href = (link.get("href") or "").strip()
        label = clean_text(link).upper()
        absolute = urljoin(BASE_URL, href)
        if "CVRF" in label or "/cvrf/" in href.lower():
            cvrf_url = absolute
        if "CSAF" in label or "/csaf/" in href.lower():
            csaf_url = _resolve_csaf_url(absolute, href)
    return cvrf_url, csaf_url


def _resolve_csaf_url(absolute: str, href: str) -> str:
    parsed = urlparse(urljoin(BASE_URL, href))
    query = parse_qs(parsed.query)
    candidates = query.get("csaf_url") or query.get("csaf_url".replace("_", "%5F")) or []
    # FortiGuard sometimes encodes as csaf_url / csaf%5Furl
    if not candidates:
        for key, values in query.items():
            if key.replace("%5F", "_").lower() == "csaf_url" and values:
                candidates = values
                break
    if candidates and candidates[0].strip():
        return candidates[0].strip()
    return absolute


def _timeline(parsed) -> list[dict[str, str | None]]:
    text = _section_paragraph(parsed, "Timeline")
    if not text:
        return []
    entries: list[dict[str, str | None]] = []
    for line in text.split("\n"):
        line = clean_text(line)
        if not line:
            continue
        if ":" in line:
            date_part, event = line.split(":", 1)
            entries.append({"date": iso_date(date_part) or clean_text(date_part), "text": clean_text(event) or None})
        else:
            entries.append({"date": iso_date(line), "text": line})
    return entries


def _affected_products(parsed) -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for table in parsed.select("div.detail-item table"):
        headers = [clean_text(node).lower() for node in table.select("thead th, tr th")]
        if not headers:
            # first row may be header-like
            first = table.select_one("tr")
            if first:
                headers = [clean_text(node).lower() for node in first.find_all(["th", "td"], recursive=False)]
        if not any("version" in header for header in headers):
            continue
        body_rows = table.select("tbody tr") or table.select("tr")[1:]
        for row in body_rows:
            cells = [clean_text(node) for node in row.find_all(["td", "th"], recursive=False)]
            if len(cells) < 3:
                continue
            if cells[0].lower() == "version":
                continue
            rows.append(
                {
                    "version": cells[0] or None,
                    "affected": cells[1] or None,
                    "solution": cells[2] or None,
                }
            )
        if rows:
            break
    return rows
