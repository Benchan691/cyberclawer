from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.zimbra.config import BASE_URL, SOURCE_URL


PATCH_LABEL_RE = re.compile(r"^Patch\s+(.+)$", re.IGNORECASE)
PATCH_PATH_RE = re.compile(
    r"^/wiki/Zimbra_Releases/(?P<code>\d+(?:\.\d+){2}(?:/P\d+)?)$"
)


def parse_release_list(
    html: str,
    *,
    page: int,
    provider: str = "zimbra",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    soup = BeautifulSoup(html, "html.parser")
    entries: list[ListEntry] = []
    seen: set[str] = set()

    for link in soup.select("a[href]"):
        label = _clean_text(link)
        if not PATCH_LABEL_RE.match(label):
            continue
        detail_url = urljoin(BASE_URL, str(link["href"]))
        code = _patch_code(detail_url)
        if not code or code in seen:
            continue
        seen.add(code)
        entries.append(_entry_from_link(link, code, detail_url, provider, source_url))

    return ListPage(page=page, entries=entries, total_pages=1, total_records=len(entries))


def _entry_from_link(
    link: Tag,
    code: str,
    detail_url: str,
    provider: str,
    source_url: str | None,
) -> ListEntry:
    row = link.find_parent("tr")
    cells = row.find_all(["td", "th"], recursive=False) if row else []
    patch_label = _clean_text(link)
    version = code
    product_release = _clean_text(cells[0]) if len(cells) > 0 else None
    codename = _clean_text(cells[1]) if len(cells) > 1 else None
    third_party_patch_level = _clean_text(cells[3]) if len(cells) > 3 else None
    general_availability = _clean_text(cells[4]) if len(cells) > 4 else None

    return ListEntry(
        identity=VulnerabilityId(type="ZIMBRA", code=code),
        title=f"Zimbra {version} Patch Release",
        vuln_type="Patch Release",
        disclosure_date=None,
        status="Patch Release",
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "version": version,
            "patch_label": patch_label,
            "product_release": product_release,
            "codename": codename,
            "third_party_patch_level": third_party_patch_level,
            "general_availability": general_availability,
            "reference_links": [detail_url],
        },
    )


def _patch_code(url: str) -> str | None:
    parsed = urlparse(url)
    match = PATCH_PATH_RE.fullmatch(parsed.path.rstrip("/"))
    return match.group("code") if match else None


def _clean_text(node: object) -> str:
    text = node.get_text(" ", strip=True) if isinstance(node, Tag) else str(node)
    return " ".join(text.replace("\xa0", " ").split())
