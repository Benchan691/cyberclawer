from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.rss import parse_rss
from vuln_scraper.scrapers.zimbra.config import BASE_URL, SOURCE_URL
from vuln_scraper.scrapers.zimbra.parsers.list import _patch_code


def parse_rss_list(xml: str, *, page: int, provider: str, source_url: str = SOURCE_URL) -> ListPage:
    items = parse_rss(xml, source="Zimbra Wiki")
    revisions: dict[str, str | None] = {}
    has_wiki_items = False
    for item in items:
        try:
            link = urlsplit(item.link)
        except ValueError:
            continue
        if link.scheme != "https" or link.netloc != "wiki.zimbra.com":
            continue
        has_wiki_items = True
        if link.path == "/index.php":
            titles = parse_qs(link.query).get("title", [])
            if len(titles) != 1:
                continue
            path = f"/wiki/{titles[0].replace(' ', '_')}"
        else:
            path = unquote(link.path)
        code = _patch_code(path)
        if code and (code not in revisions or (item.published_at or "") > (revisions[code] or "")):
            revisions[code] = item.published_at

    if items and not has_wiki_items:
        raise ValueError("Zimbra RSS contains no official Wiki changes")

    entries = [
        ListEntry(
            identity=VulnerabilityId("ZIMBRA", code),
            title=f"Zimbra {code} Patch Release",
            vuln_type="Patch Release",
            disclosure_date=None,
            status="Patch Release",
            provider=provider,
            source_url=source_url,
            embedded_detail={
                "_list_summary": True,
                "version": code,
                "updated_at": revision_at,
                "reference_links": [f"{BASE_URL}/wiki/Zimbra_Releases/{code}"],
            },
        )
        for code, revision_at in sorted(revisions.items(), key=lambda revision: revision[1] or "", reverse=True)
    ]
    return ListPage(page, entries, total_pages=1, total_records=len(entries), exhausted=not entries)
