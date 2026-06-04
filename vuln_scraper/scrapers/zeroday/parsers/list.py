from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.zeroday.config import BASE_URL


DATABASE_ID_RE = re.compile(r"^/database/(\d+)/?$")
TOTAL_RECORDS_RE = re.compile(r"Zero-day vulnerabilities discovered:\s*([\d,]+)", re.IGNORECASE)


def parse_database_list(
    html: str,
    *,
    page: int,
    provider: str = "zeroday",
    source_url: str | None = None,
) -> ListPage:
    soup = _soup(html)
    entries: list[ListEntry] = []

    for issue in soup.select("#issuew_wrap .issue"):
        identity_code = _identity_code(issue)
        if not identity_code:
            continue

        cve_id = _clean_text(issue.select_one(".issue-code")) or None
        title = _title(issue, cve_id)
        if not title:
            continue

        patched_date = _clean_text(issue.select_one(".patched time")) or None
        detail = {
            "_list_summary": True,
            "cve_id": cve_id,
            "weakness": _clean_text(issue.select_one(".description .desc-title")) or None,
            "summary": _description(issue),
            "software": _clean_text(issue.select_one(".spec strong")) or None,
            "disclosed_date": _clean_text(issue.select_one(".discavered time")) or None,
            "patched_date": patched_date,
            "patch_status": _patch_status(patched_date),
            "reference_links": _links(issue.select(".issue-links a[href]")),
        }

        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="ZERODAY", code=identity_code),
                title=title,
                vuln_type=detail["weakness"],
                disclosure_date=detail["disclosed_date"],
                status=detail["patch_status"],
                provider=provider,
                source_url=source_url,
                embedded_detail=detail,
            )
        )

    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=_parse_total_records(soup) or len(entries),
    )


def _identity_code(issue: Tag) -> str | None:
    link = issue.select_one(".issue-title a[href]")
    if link is None:
        return None
    path = urlparse(urljoin(BASE_URL, str(link["href"]))).path
    match = DATABASE_ID_RE.fullmatch(path)
    return match.group(1) if match else None


def _title(issue: Tag, cve_id: str | None) -> str | None:
    link = issue.select_one(".issue-title a[href]")
    title = _clean_text(link)
    if cve_id and title.endswith(cve_id):
        title = title[: -len(cve_id)].strip()
    return title or None


def _description(issue: Tag) -> str | None:
    description = issue.select_one(".description")
    if description is None:
        return None
    return _clean_multiline(description) or None


def _links(links: list[Tag]) -> list[str]:
    result: list[str] = []
    for link in links:
        href = urljoin(BASE_URL, str(link["href"]))
        if href not in result:
            result.append(href)
    return result


def _patch_status(patched_date: str | None) -> str:
    return "patched" if patched_date else "unpatched"


def _parse_total_records(soup: BeautifulSoup) -> int | None:
    text = _clean_text(soup)
    match = TOTAL_RECORDS_RE.search(text)
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


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
