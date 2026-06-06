from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.juniper.config import (
    ARTICLE_URL,
    COVEO_LIST_QUERY,
    DEFAULT_COLLECTION,
    PAGE_SIZE,
    SEARCH_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.juniper.coveo import (
    ARTICLE_RAW_FIELDS,
    DEFAULT_FACETS,
    coveo_search_body,
    coveo_search_url,
    get_coveo_config,
)
from vuln_scraper.scrapers.juniper.parsers.coveo import parse_coveo_detail, parse_coveo_list
from vuln_scraper.scrapers.juniper.parsers.detail import JuniperDetailRecord
from vuln_scraper.scrapers.juniper.parsers.list import parse_advisory_list


def _slug_from_detail_url(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    if "/s/article/" not in path:
        raise ValueError(f"Not a Juniper article URL: {url}")
    slug = path.split("/s/article/", 1)[-1]
    if not slug:
        raise ValueError(f"Missing article slug in URL: {url}")
    return slug


@dataclass(slots=True)
class JuniperProvider:
    key: str = "juniper"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    always_use_browser: bool = False
    content_type: str = "json"
    default_request_delay: float = 1.5
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        first_result = max(0, (max(1, page) - 1) * PAGE_SIZE)
        fragment = (
            "f-sf_primarysourcename=Knowledge"
            "&f-sf_articletype=Security%20Advisories"
            f"&firstResult={first_result}"
        )
        return f"{SEARCH_URL}#{fragment}"

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("JUNIPER-").strip()
        if not code:
            raise ValueError(f"invalid Juniper advisory identifier: {identity_display!r}")
        return f"{ARTICLE_URL}/{quote(code, safe='')}"

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        links = detail.get("reference_links")
        if isinstance(links, list):
            for link in links:
                if isinstance(link, str) and link.strip():
                    return link.strip()
        slug = detail.get("slug")
        if isinstance(slug, str) and slug.strip():
            return f"{ARTICLE_URL}/{quote(slug.strip(), safe='')}"
        return self.detail_url(entry.display_id)

    def list_json_request(self, page: int, *, checkpoint: object | None = None) -> dict[str, Any]:
        cfg = get_coveo_config(page_uri="/s/global-search/@uri")
        first_result = max(0, (max(1, page) - 1) * PAGE_SIZE)
        return {
            "method": "POST",
            "url": coveo_search_url(cfg),
            "headers": {
                "Authorization": f"Bearer {cfg['accessToken']}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            "json": coveo_search_body(
                q=COVEO_LIST_QUERY,
                first_result=first_result,
                number_of_results=PAGE_SIZE,
                facet_filters=list(DEFAULT_FACETS),
            ),
        }

    def detail_json_request(self, entry: ListEntry, *, detail_url: str) -> dict[str, Any]:
        slug = _slug_from_detail_url(detail_url)
        cfg = get_coveo_config(page_uri=f"/s/article/{slug}")
        return {
            "method": "POST",
            "url": coveo_search_url(cfg),
            "headers": {
                "Authorization": f"Bearer {cfg['accessToken']}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            "json": coveo_search_body(
                q=f'@sfurlname=="{slug}"',
                number_of_results=1,
                fields_to_include=ARTICLE_RAW_FIELDS,
            ),
        }

    def parse_list(self, data: object, *, page: int) -> ListPage:
        if isinstance(data, dict) and "results" in data:
            return parse_coveo_list(data, page=page, provider=self.key, source_url=self.source_url)
        if isinstance(data, str):
            return parse_advisory_list(data, page=page, provider=self.key, source_url=self.source_url)
        raise TypeError(f"unsupported Juniper list payload: {type(data)!r}")

    def parse_detail(self, data: object) -> JuniperDetailRecord:
        if isinstance(data, dict) and "results" in data:
            return parse_coveo_detail(data)
        if isinstance(data, str):
            from vuln_scraper.scrapers.juniper.parsers.detail import parse_detail_page

            return parse_detail_page(data)
        raise TypeError(f"unsupported Juniper detail payload: {type(data)!r}")

    def finalize_detail(self, detail: dict[str, Any], *, entry: ListEntry, detail_url: str) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in ("article_id", "published_date", "updated_date", "article_type", "source_name", "summary"):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)
        links = list(merged.get("reference_links") or [])
        if detail_url not in links:
            links.insert(0, detail_url)
        merged["reference_links"] = links
        return merged
