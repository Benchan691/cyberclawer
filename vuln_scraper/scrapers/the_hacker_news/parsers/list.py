from __future__ import annotations

from xml.etree import ElementTree

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.the_hacker_news.config import SOURCE_URL
from vuln_scraper.scrapers.the_hacker_news.parsers.common import (
    article_code, article_url, clean_text, cve_ids, normalized_date,
)


def parse_rss_list(
    xml: str, *, page: int, provider: str = "the_hacker_news", source_url: str = SOURCE_URL,
) -> ListPage:
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, TypeError, ValueError) as exc:
        raise ValueError("Invalid The Hacker News RSS feed") from exc
    channel = next((child for child in root if _name(child.tag) == "channel"), None)
    if _name(root.tag) != "rss" or channel is None:
        raise ValueError("The Hacker News RSS feed is missing its RSS channel")

    entries: list[ListEntry] = []
    seen: set[str] = set()
    items = [child for child in channel if _name(child.tag) == "item"]
    for item in items:
        fields = {_name(child.tag): "".join(child.itertext()).strip() for child in item}
        url = next((url for field in ("origLink", "link", "guid")
                    if (url := article_url(fields.get(field, "")))), None)
        title = clean_text(fields.get("title", ""))
        if not url or not title:
            continue
        code = article_code(url)
        if code in seen:
            continue
        seen.add(code)
        published_at = normalized_date(fields.get("pubDate", ""))
        summary = clean_text(fields.get("description", ""))
        categories = list(dict.fromkeys(clean_text("".join(child.itertext())) for child in item
                                       if _name(child.tag) == "category" and "".join(child.itertext()).strip()))
        entries.append(ListEntry(
            identity=VulnerabilityId(type="THN", code=code),
            title=title, vuln_type=None,
            disclosure_date=published_at[:10] if published_at else None,
            status=None, provider=provider, source_url=source_url,
            embedded_detail={
                "_list_summary": True,
                "feed_guid": fields.get("guid") or url,
                "title": title, "article_url": url,
                "published_at": published_at, "summary": summary or None,
                "author": fields.get("creator") or fields.get("author") or None,
                "categories": categories, "cve_ids": cve_ids(f"{title}\n{summary}"),
                "reference_links": [url],
            },
        ))
    if items and not entries:
        raise ValueError("The Hacker News RSS feed contains items but no valid articles")
    return ListPage(page=page, entries=entries, total_pages=1, total_records=len(entries),
                    start_index=0, results_per_page=len(entries), exhausted=not items)


def _name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]
