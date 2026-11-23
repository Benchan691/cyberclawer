from __future__ import annotations

from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urljoin, urlparse
from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.govcert.config import BASE_URL, DETAIL_URL, SOURCE_URL
from vuln_scraper.scrapers.govcert.parsers.common import (
    clean_text,
    parse_alert_title,
    severity_from_title,
    soup,
)


DETAIL_PATH = "/en/alerts_detail.php"
EN_BASE_URL = f"{BASE_URL}/en/"


def parse_alerts_list(
    xml: str,
    *,
    page: int,
    provider: str = "govcert",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    root = ElementTree.fromstring(xml)
    channel = root.find("{*}channel") if root.tag.rsplit("}", 1)[-1] == "rss" else None
    if channel is None:
        raise ValueError("GovCERT feed must contain an RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = channel.findall("{*}item")
    for item in items:
        code = _identity_code(item.findtext("{*}link", "")) or _identity_code(item.findtext("{*}guid", ""))
        alert_code, alert_type, title = parse_alert_title(item.findtext("{*}title", ""))
        if code is None or code in seen or not title:
            continue
        seen.add(code)

        published_date = _publication_date(item.findtext("{*}pubDate", "").strip())
        description = clean_text(soup(item.findtext("{*}description", "").strip()))
        entries.append(
            ListEntry(
                identity=VulnerabilityId(type="GOVCERT", code=code),
                title=title,
                vuln_type=alert_code,
                disclosure_date=published_date,
                status=alert_type,
                provider=provider,
                source_url=source_url,
                embedded_detail={
                    "_list_summary": True,
                    "alert_code": alert_code,
                    "alert_type": alert_type,
                    "severity": severity_from_title(title),
                    "published_date": published_date,
                    "description": description or None,
                    "detail_url": f"{DETAIL_URL}?id={code}",
                },
            )
        )

    if items and not entries:
        raise ValueError("GovCERT feed did not contain valid English alert entries")
    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        exhausted=not items,
    )


def _identity_code(href: str) -> str | None:
    try:
        parsed = urlparse(urljoin(EN_BASE_URL, href.strip()))
    except ValueError:
        return None
    if parsed.scheme != "https" or parsed.netloc.lower() != urlparse(BASE_URL).netloc or parsed.path != DETAIL_PATH:
        return None
    identities = parse_qs(parsed.query).get("id", [])
    if len(identities) == 1 and identities[0].isascii() and identities[0].isdigit():
        return identities[0]
    return None


def _publication_date(value: str) -> str | None:
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError, OverflowError):
        return None
