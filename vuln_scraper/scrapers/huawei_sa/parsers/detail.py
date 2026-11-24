from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from vuln_scraper.rss import rss_date


@dataclass(slots=True)
class HuaweiSADetailRecord:
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.raw)


def parse_detail_payload(content: Any) -> HuaweiSADetailRecord:
    if isinstance(content, dict):
        return HuaweiSADetailRecord(raw=content)
    return HuaweiSADetailRecord()


def parse_detail_page(html: str) -> HuaweiSADetailRecord:
    soup = BeautifulSoup(html, "lxml")
    root = soup.select_one(".psiet-detail, .psirt-detail")
    title = root.select_one("h1") if root else None
    sections = {}
    if root is None or title is None:
        raise ValueError("Huawei SA detail page is missing its full security advisory")
    for section in root.select(".psirt-set-out"):
        label = section.select_one("[data-collapse]")
        content = section.select_one(".moreinfo")
        if label and content:
            sections[str(label.get("data-collapse")).strip()] = content.get_text("\n", strip=True)
    summary = sections.get("Summary", "")
    if not summary:
        raise ValueError("Huawei SA detail page is missing its summary")
    text = root.get_text(" ", strip=True)

    def date(label: str) -> str | None:
        match = re.search(rf"{label}\s*:\s*(\d{{4}}-\d{{2}}-\d{{2}})", text, re.IGNORECASE)
        return rss_date(match.group(1)) if match else None

    scores = [float(score) for score in re.findall(r"\bBase Score\s*:\s*(10(?:\.0)?|[0-9](?:\.\d+)?)\b",
                                                  sections.get("Vulnerability Scoring Details", ""))]
    score = max(scores, default=None)
    severity = None if score is None else (
        "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low")
    links = []
    for anchor in root.select("a[href]"):
        url = urljoin("https://www.huawei.com", str(anchor["href"]))
        if urlsplit(url).scheme in {"https", "http"} and url not in links:
            links.append(url)
    identifier = re.search(r"SA No\s*:\s*([^\s]+)", text, re.IGNORECASE)
    return HuaweiSADetailRecord(raw={
        "title": title.get_text(" ", strip=True),
        "advisory_id": identifier.group(1) if identifier else None,
        "publishDate": date("Initial Release Date"), "updated_at": date("Last Release Date"),
        "summary": summary, "description": summary, "content": root.get_text("\n", strip=True),
        "severity": severity, "cvss_score": score,
        "cve_ids": list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE))),
        "affected_products": sections.get("Software Versions and Fixes"),
        "impact_description": sections.get("Impact"), "solution": sections.get("Obtaining Fixed Software"),
        "reference_links": links, "raw_sections": sections,
    })
