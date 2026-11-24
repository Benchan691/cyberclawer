from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.huawei_sa.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL
from vuln_scraper.scrapers.huawei_sa.parsers.detail import HuaweiSADetailRecord, parse_detail_page
from vuln_scraper.scrapers.huawei_sa.parsers.rss import advisory_url, parse_rss_list


PROVIDER_SCHEMA = {
    "identity_fields": ("sasnNo", "sasnId", "advisory_id"), "title_fields": ("title",),
    "cve_fields": ("cve_ids",), "severity_fields": ("severity",),
    "published_fields": ("publishDate",), "updated_fields": ("updated_at",),
}


@dataclass(frozen=True, slots=True)
class HuaweiSAProvider:
    key: str = "huawei_sa"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "html"
    default_request_delay: float = 1.2
    stop_on_first_known: bool = False
    catch_up_full_feed: bool = True
    sync_discovery_version: str = "rss-v1"

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        code = identity_display.removeprefix("HUAWEI_SA-").strip()
        if not code:
            raise ValueError("Huawei SA advisory identifier is empty")
        return f"{DETAIL_URL}/{quote(code, safe='')}"

    def detail_url_for_entry(self, entry: ListEntry) -> str:
        saved = (entry.embedded_detail or {}).get("detail_url")
        if saved:
            url = advisory_url(str(saved))
            if url is None:
                raise ValueError("Invalid Huawei SA advisory URL")
            return url
        return self.detail_url(entry.display_id)

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> HuaweiSADetailRecord:
        return parse_detail_page(html)
