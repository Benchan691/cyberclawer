from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.zimbra.config import BASE_URL


DATE_RE = re.compile(
    r"Release Date\s*:\s*(\w+\s+\d{1,2},\s+\d{4}|\d{4}-\d{1,2}-\d{1,2})",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"v?(\d+(?:\.\d+){2}(?:/P\d+)?)", re.IGNORECASE)
PACKAGE_RE = re.compile(r"^\s*(\S+)\s*[-=]>\s*(\S+)\s*$")


@dataclass(slots=True)
class ZimbraDetailRecord:
    title: str | None = None
    version: str | None = None
    release_date: str | None = None
    security_fixes: list[str] = field(default_factory=list)
    fixed_issues: dict[str, list[str]] = field(default_factory=dict)
    packages: dict[str, str] = field(default_factory=dict)
    patch_installation_url: str | None = None
    open_source_repo_url: str | None = None
    reference_links: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> ZimbraDetailRecord:
    soup = BeautifulSoup(html, "html.parser")
    root = soup.select_one("#mw-content-text .mw-parser-output") or soup
    headings = [
        heading
        for heading in root.find_all(["h1", "h2", "h3"])
        if heading.find_parent(id="toc") is None
    ]
    title = next((_clean_text(heading) for heading in headings if _clean_text(heading)), None)
    raw_sections = {
        _key(_clean_text(heading)): _section_text(heading)
        for heading in headings
        if _key(_clean_text(heading)) not in {"contents", "jump to"}
    }

    release_date = _iso_date(_first_match(DATE_RE, root.get_text(" ", strip=True)))
    version_match = VERSION_RE.search(title or "")

    security_heading = _find_heading(headings, "security fixes")
    security_fixes = _table_cells_between(security_heading) if security_heading else []
    if security_heading and not security_fixes:
        security_fixes = _items_between(security_heading)

    fixed_issues: dict[str, list[str]] = {}
    fixed_heading = _find_heading(headings, "fixed issues")
    if fixed_heading:
        for heading in _subheadings_after(fixed_heading, headings):
            fixed_issues[_clean_text(heading)] = _items_between(heading)

    packages_heading = _find_heading(headings, "packages")
    packages = _packages_between(packages_heading) if packages_heading else {}
    patch_heading = _find_heading(headings, "patch installation")
    patch_url = _first_link(patch_heading, "patch_installation") if patch_heading else None
    repo_url = _first_matching_link(root, "github.com/Zimbra/")

    return ZimbraDetailRecord(
        title=title,
        version=version_match.group(1) if version_match else None,
        release_date=release_date,
        security_fixes=security_fixes,
        fixed_issues=fixed_issues,
        packages=packages,
        patch_installation_url=patch_url,
        open_source_repo_url=repo_url,
        reference_links=_links(root),
        raw_sections=raw_sections,
    )


def _find_heading(headings: list[Tag], name: str) -> Tag | None:
    wanted = _key(name)
    return next((heading for heading in headings if _key(_clean_text(heading)) == wanted), None)


def _section_text(heading: Tag) -> str:
    return "\n".join(_clean_text(node) for node in _nodes_between(heading) if _clean_text(node))


def _nodes_between(heading: Tag) -> list[Tag]:
    level = int(heading.name[1])
    nodes: list[Tag] = []
    for sibling in heading.next_siblings:
        if not isinstance(sibling, Tag):
            continue
        if sibling.name in {"h1", "h2", "h3"} and int(sibling.name[1]) <= level:
            break
        nodes.append(sibling)
    return nodes


def _subheadings_after(heading: Tag, headings: list[Tag]) -> list[Tag]:
    index = headings.index(heading)
    result: list[Tag] = []
    for candidate in headings[index + 1 :]:
        if candidate.name == "h1":
            break
        if candidate.name == "h2":
            result.append(candidate)
    return result


def _items_between(heading: Tag) -> list[str]:
    items: list[str] = []
    for node in _nodes_between(heading):
        if node.name in {"ul", "ol"}:
            items.extend(_clean_text(item) for item in node.find_all("li"))
        elif node.name in {"p", "div"}:
            text = _clean_text(node)
            if text:
                items.append(text)
    return [item for item in items if item]


def _table_cells_between(heading: Tag) -> list[str]:
    values: list[str] = []
    for node in _nodes_between(heading):
        if node.name == "table":
            values.extend(_clean_text(cell) for cell in node.select("td"))
    return [value for value in values if value]


def _packages_between(heading: Tag) -> dict[str, str]:
    packages: dict[str, str] = {}
    for node in _nodes_between(heading):
        if node.name != "pre":
            continue
        for line in node.get_text("\n").splitlines():
            match = PACKAGE_RE.match(line)
            if match:
                packages[match.group(1)] = match.group(2)
    return packages


def _first_link(heading: Tag, needle: str) -> str | None:
    for node in _nodes_between(heading):
        for link in node.select("a[href]"):
            href = urljoin(BASE_URL, str(link["href"]))
            if needle.lower() in href.lower():
                return href
    return None


def _first_matching_link(root: Tag, needle: str) -> str | None:
    for link in root.select("a[href]"):
        href = urljoin(BASE_URL, str(link["href"]))
        if needle.lower() in href.lower():
            return href
    return None


def _links(root: Tag) -> list[str]:
    links: list[str] = []
    for link in root.select("a[href]"):
        href = urljoin(BASE_URL, str(link["href"]))
        if href not in links and ("patch_installation" in href or "github.com/Zimbra/" in href):
            links.append(href)
    return links


def _key(value: str) -> str:
    return " ".join(value.lower().rstrip(":").split())


def _clean_text(node: object) -> str:
    text = node.get_text(" ", strip=True) if isinstance(node, Tag) else str(node)
    return " ".join(text.replace("\xa0", " ").split())


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    for format_string in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), format_string).date().isoformat()
        except ValueError:
            pass
    return value.strip()
