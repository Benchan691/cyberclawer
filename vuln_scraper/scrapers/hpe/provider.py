from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.scrapers.hpe.config import (
    DEFAULT_COLLECTION,
    DOCUMENT_API_URL,
    LIST_URL,
    SOURCE_URL,
)
from vuln_scraper.scrapers.hpe.parsers.detail import HPEDetailRecord, parse_detail_page
from vuln_scraper.scrapers.hpe.parsers.list import parse_rss_list


@dataclass(frozen=True, slots=True)
class HPEProvider:
    key: str = "hpe"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    browser_fallback: bool = False
    always_use_browser: bool = False
    content_type: str = "html"
    default_request_delay: float = 1.0
    stop_on_first_known: bool = True

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        return self._document_url(_doc_id_from_identity(identity_display))

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        doc_id = detail.get("doc_id")
        if isinstance(doc_id, str) and doc_id.strip():
            return self._document_url(doc_id)
        try:
            return self.detail_url(entry.display_id)
        except ValueError:
            return None

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, html: str) -> HPEDetailRecord:
        return parse_detail_page(html)

    def finalize_detail(
        self,
        detail: dict[str, Any],
        *,
        entry: ListEntry,
        detail_url: str,
    ) -> dict[str, Any]:
        merged = dict(detail)
        list_detail = entry.embedded_detail if isinstance(entry.embedded_detail, dict) else {}
        for key in (
            "title",
            "bulletin_id",
            "doc_id",
            "doc_display_url",
            "published_date",
            "severity",
            "summary",
        ):
            if merged.get(key) in (None, "", []):
                merged[key] = list_detail.get(key)

        if merged.get("release_date") in (None, ""):
            merged["release_date"] = entry.disclosure_date

        links = list(merged.get("reference_links") or [])
        doc_display_url = merged.get("doc_display_url")
        if isinstance(doc_display_url, str) and doc_display_url and doc_display_url not in links:
            links.insert(0, doc_display_url)
        merged["reference_links"] = links
        return merged

    @staticmethod
    def _document_url(doc_id: str) -> str:
        normalized = doc_id.strip().casefold()
        if not normalized or not normalized.startswith("hpesb"):
            raise ValueError(f"invalid HPE security bulletin identifier: {doc_id!r}")
        return f"{DOCUMENT_API_URL}/{quote(normalized, safe='')}"


def _doc_id_from_identity(identity_display: str) -> str:
    value = identity_display.strip()
    if value.upper().startswith("HPE-"):
        value = value[4:]
    if not value:
        raise ValueError(f"invalid HPE security bulletin identifier: {identity_display!r}")
    return value
