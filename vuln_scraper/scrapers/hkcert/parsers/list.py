from __future__ import annotations

from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.hkcert.config import BASE_URL, SOURCE_URL


BULLETIN_PATH = "/security-bulletin/"


def parse_security_bulletin_list(
    xml: str,
    *,
    page: int,
    provider: str = "hkcert",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    root = ElementTree.fromstring(xml)
    channel = root.find("{*}channel") if root.tag.rsplit("}", 1)[-1] == "rss" else None
    if channel is None:
        raise ValueError("HKCERT feed must contain an RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = channel.findall("{*}item")
    for item in items:
        slug = _bulletin_slug(item.findtext("{*}link", "")) or _bulletin_slug(item.findtext("{*}guid", ""))
        title = " ".join(item.findtext("{*}title", "").split())
        if slug is None or slug in seen or not title:
            continue
        seen.add(slug)

        release_date = _publication_date(item.findtext("{*}pubDate", "").strip())
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="HKCERT", code=slug),
                title=title,
                vuln_type=None,
                disclosure_date=release_date,
                status=None,
                provider=provider,
                source_url=source_url,
                embedded_detail={"_list_summary": True},
            )
        )

    if items and not entries:
        raise ValueError("HKCERT feed did not contain valid English bulletin entries")
    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        exhausted=not items,
    )


def _bulletin_slug(link: str) -> str | None:
    try:
        target = urlsplit(urljoin(f"{BASE_URL}/", link.strip()))
    except ValueError:
        return None
    if (
        target.scheme != "https"
        or target.netloc.lower() != urlsplit(BASE_URL).netloc
        or not target.path.startswith(BULLETIN_PATH)
    ):
        return None
    slug = target.path.removeprefix(BULLETIN_PATH).rstrip("/")
    if slug and "/" not in slug and slug not in {".", ".."}:
        return slug
    return None


def _publication_date(value: str) -> str | None:
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError, OverflowError):
        return None
