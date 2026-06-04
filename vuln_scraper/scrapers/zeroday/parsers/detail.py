from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from vuln_scraper.scrapers.zeroday.config import BASE_URL


URL_RE = re.compile(r"https?://[^\s<>\"]+")
CWE_RE = re.compile(r"(CWE-\d+)\s*(?:-\s*(.+))?", re.IGNORECASE)


@dataclass(slots=True)
class ZeroDayDetailRecord:
    cve_id: str | None = None
    advisory: dict[str, str | None] | None = None
    vulnerable_component: str | None = None
    cvss_v3_vector: str | None = None
    cwe: dict[str, str | None] | None = None
    description: str | None = None
    disclosed_date: str | None = None
    patched_date: str | None = None
    patch_status: str | None = None
    reference_links: list[str] = field(default_factory=list)
    weakness: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> ZeroDayDetailRecord:
    soup = _soup(html)
    issue = soup.select_one("#last_vulnerabilities .issue") or soup.select_one(".issue")
    if issue is None:
        return ZeroDayDetailRecord()

    patched_date = _clean_text(issue.select_one(".patched time")) or None
    return ZeroDayDetailRecord(
        cve_id=_clean_text(issue.select_one(".issue-code")) or _field_value(issue, "CVE-ID"),
        advisory=_advisory(issue),
        vulnerable_component=_field_value(issue, "Vulnerable component"),
        cvss_v3_vector=_field_value(issue, "CVSSv3 score"),
        cwe=_cwe(_field_value(issue, "CWE-ID")),
        description=_section_after_label(issue, "Description"),
        disclosed_date=_clean_text(issue.select_one(".discavered time")) or None,
        patched_date=patched_date,
        patch_status=_patch_status(patched_date),
        reference_links=_external_links(issue),
        weakness=_weakness(issue),
    )


def _advisory(issue: Tag) -> dict[str, str | None] | None:
    paragraph = _label_paragraph(issue, "Advisory")
    if paragraph is None:
        return None
    link = paragraph.find("a", href=True)
    if link is not None:
        return {
            "title": _clean_text(link) or None,
            "url": urljoin(BASE_URL, str(link["href"])),
        }
    value = _value_from_labeled_paragraph(paragraph, "Advisory")
    return {"title": value, "url": None} if value else None


def _field_value(issue: Tag, label: str) -> str | None:
    paragraph = _label_paragraph(issue, label)
    if paragraph is None:
        return None
    return _value_from_labeled_paragraph(paragraph, label)


def _value_from_labeled_paragraph(paragraph: Tag, label: str) -> str | None:
    text = _clean_text(paragraph)
    text = re.sub(rf"^{re.escape(label)}\s*:?\s*", "", text, flags=re.IGNORECASE).strip()
    return text or None


def _cwe(value: str | None) -> dict[str, str | None] | None:
    if not value:
        return None
    match = CWE_RE.search(value)
    if not match:
        return {"id": None, "name": value}
    cwe_id, name = match.groups()
    return {"id": cwe_id.upper(), "name": name.strip() if name else None}


def _section_after_label(issue: Tag, label: str) -> str | None:
    paragraph = _label_paragraph(issue, label)
    if paragraph is None:
        return None

    texts: list[str] = []
    for sibling in paragraph.next_siblings:
        if isinstance(sibling, Tag):
            if sibling.find("b"):
                break
            text = _clean_multiline(sibling)
            if text:
                texts.append(text)
    return "\n".join(texts) or None


def _external_links(issue: Tag) -> list[str]:
    text = _section_after_label(issue, "External links") or ""
    links: list[str] = []
    paragraph = _label_paragraph(issue, "External links")
    if paragraph is not None:
        for sibling in paragraph.next_siblings:
            if isinstance(sibling, Tag):
                if sibling.find("b"):
                    break
                for link in sibling.find_all("a", href=True):
                    href = urljoin(BASE_URL, str(link["href"]))
                    if href not in links:
                        links.append(href)

    for match in URL_RE.findall(text):
        url = match.rstrip(").,;")
        if url not in links:
            links.append(url)
    return links


def _weakness(issue: Tag) -> str | None:
    title = _clean_text(issue.select_one(".issue-title"))
    cve_id = _clean_text(issue.select_one(".issue-code"))
    if cve_id and title.endswith(cve_id):
        title = title[: -len(cve_id)].strip()
    return title or None


def _label_paragraph(issue: Tag, label: str) -> Tag | None:
    expected = label.casefold()
    for paragraph in issue.find_all("p"):
        bold = paragraph.find("b")
        if bold and _clean_text(bold).rstrip(":").casefold() == expected:
            return paragraph
    return None


def _patch_status(patched_date: str | None) -> str:
    return "patched" if patched_date else "unpatched"


def _soup(html: str) -> BeautifulSoup:
    safe_html = html.encode("utf-8", "replace").decode("utf-8", "replace")
    return BeautifulSoup(safe_html, "lxml")


def _clean_text(node) -> str:
    if node is None:
        return ""
    return " ".join(node.get_text(" ", strip=True).split())


def _clean_multiline(node) -> str:
    if node is None:
        return ""
    lines = [line.strip() for line in node.get_text("\n", strip=True).splitlines()]
    return "\n".join(line for line in lines if line and line != "\xa0")
