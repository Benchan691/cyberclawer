from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.wiz.config import BASE_URL
from vuln_scraper.scrapers.wiz.parsers.common import cve_ids, incident_url, normalized_date


@dataclass(slots=True)
class WizDetailRecord:
    title: str
    content: str
    article_url: str | None = None
    summary: str | None = None
    threat_type: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    actors: list[str] = field(default_factory=list)
    initial_access: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    observed_techniques: list[str] = field(default_factory=list)
    targeted_technologies: list[str] = field(default_factory=list)
    source_status: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> WizDetailRecord:
    soup = BeautifulSoup(html, "lxml")
    article = soup.select_one("article.notion-root")
    title_node = soup.select_one("h1.notion-header__title")
    title = _text(title_node)
    if article is None or not title:
        raise ValueError("Wiz detail page is missing its incident article or title")

    properties: dict[str, list[str]] = {}
    for row in article.select(".notion-page__property"):
        name = _text(row.select_one(".notion-page__property-name")).casefold()
        value = row.select_one(".notion-property")
        if name and value:
            values = value.select(".notion-pill, .notion-page__title")
            texts = [_text(node) for node in values] if values else [_text(value)]
            properties[name] = list(dict.fromkeys(text for text in texts if text))

    canonical = soup.select_one('link[rel="canonical"]') or soup.select_one('meta[property="og:url"]')
    url = incident_url(str(canonical.get("href") or canonical.get("content") or "")) if canonical else None
    links: list[str] = []
    for anchor in article.select("a[href]"):
        link = urljoin(url or BASE_URL, str(anchor["href"]))
        if urlparse(link).scheme in {"https", "http"} and link not in links:
            links.append(link)
    for node in article.select(".notion-page__properties, script, style, nav, footer, svg"):
        node.decompose()
    content = "\n".join(_text(node) for node in article.find_all(recursive=False) if _text(node))
    description = soup.select_one('meta[name="description"]')
    summary = str(description.get("content") or "").strip() if description else None
    if not content:
        # Some historical incidents consist entirely of structured properties.
        metadata = "\n".join(f"{name}: {', '.join(values)}" for name, values in properties.items() if values)
        if not metadata:
            raise ValueError("Wiz detail page is missing its incident content")
        content = "\n".join(part for part in (summary, metadata) if part)
    return WizDetailRecord(
        title=title,
        content=content,
        article_url=url,
        summary=summary or None,
        threat_type=_first(properties, "type"),
        published_at=normalized_date(_first(properties, "pub. date") or ""),
        updated_at=normalized_date(_first(properties, "last edited") or ""),
        actors=properties.get("actors", []),
        initial_access=properties.get("initial access", []),
        impact=properties.get("impact", []),
        observed_techniques=properties.get("observed techniques", []),
        targeted_technologies=properties.get("targeted technologies", []),
        source_status=_first(properties, "status"),
        cve_ids=cve_ids(f"{title}\n{summary or ''}\n{content}\n{' '.join(links)}"),
        reference_links=links,
    )


def _text(node: Tag | None) -> str:
    return " ".join(node.get_text(" ", strip=True).split()) if node else ""


def _first(properties: dict[str, list[str]], key: str) -> str | None:
    values = properties.get(key, [])
    return values[0] if values else None
