from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from vuln_scraper.scrapers.the_hacker_news.config import SOURCE_URL
from vuln_scraper.scrapers.the_hacker_news.parsers.common import article_url, cve_ids, normalized_date


@dataclass(slots=True)
class TheHackerNewsDetailRecord:
    title: str
    content: str
    article_url: str | None = None
    summary: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    author: str | None = None
    categories: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    reference_links: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_detail_page(html: str) -> TheHackerNewsDetailRecord:
    soup = BeautifulSoup(html, "lxml")
    article = soup.select_one(".articlebody")
    title_node = soup.select_one("h1.story-title")
    title = title_node.get_text(" ", strip=True) if title_node else ""
    if article is None or not title:
        raise ValueError("The Hacker News detail page is missing its article or title")

    def meta(selector: str) -> str:
        node = soup.select_one(selector)
        return str(node.get("content") or node.get("datetime") or node.get_text(" ", strip=True)) if node else ""

    canonical = soup.select_one('link[rel="canonical"]')
    url = article_url(str(canonical.get("href") or "")) if canonical else None
    if canonical is not None and url is None:
        raise ValueError("The Hacker News detail page has an invalid canonical article URL")
    published_at = normalized_date(meta('[itemprop="datePublished"], meta[property="article:published_time"]'))
    updated_at = normalized_date(meta('[itemprop="dateModified"], meta[property="article:modified_time"]'))
    author = meta('[itemprop="author"] [itemprop="name"]') or meta('.p-author .author') or meta('meta[name="author"]')
    categories = list(dict.fromkeys(node.get_text(" ", strip=True)
                                   for node in soup.select('[itemprop="articleSection"]')
                                   if node.get_text(" ", strip=True)))
    summary = meta('meta[name="description"], meta[property="og:description"]')
    for node in article.select("script, style, iframe, nav, footer, form, .note-b, .categ, "
                               ".separator, .stophere, .blogger-post-footer, .adsbygoogle"):
        node.decompose()
    links: list[str] = []
    for anchor in article.select("a[href]"):
        link = urljoin(url or SOURCE_URL, str(anchor["href"]))
        parsed = urlparse(link)
        if parsed.scheme in {"http", "https"} and parsed.netloc and link not in links:
            links.append(link)
    for node in article.select("br"):
        node.replace_with("\n")
    for node in article.select("p, h2, h3, h4, li, pre, blockquote, table, tr"):
        node.insert_before("\n")
        node.insert_after("\n")
    content = "\n".join(line for raw in article.get_text(" ").splitlines() if (line := " ".join(raw.split())))
    if not content:
        raise ValueError("The Hacker News detail page is missing its article content")
    return TheHackerNewsDetailRecord(
        title=title, content=content, article_url=url, summary=summary or None,
        published_at=published_at, updated_at=updated_at, author=author or None,
        categories=categories,
        cve_ids=cve_ids(f"{title}\n{summary}\n{content}\n{' '.join(links)}"),
        reference_links=links,
    )
