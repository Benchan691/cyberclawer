from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from vuln_scraper.models import ListEntry, ListPage
from vuln_scraper.timestamps import parse_timestamp
from vuln_scraper.scrapers.msrc.config import DEFAULT_COLLECTION, DETAIL_URL, LIST_URL, SOURCE_URL, UPDATES_URL
from vuln_scraper.scrapers.msrc.parsers.detail import (
    MSRCMonthlyRecord,
    expand_cvrf_document,
    parse_cvrf_document,
)
from vuln_scraper.scrapers.msrc.parsers.list import parse_update_list
from vuln_scraper.scrapers.msrc.parsers.rss import parse_rss_list


PROVIDER_SCHEMA = {
    "identity_fields": ("cve_id",), "title_fields": ("title",), "cve_fields": ("cve_id",),
    "published_fields": ("initial_release_date",),
    "updated_fields": ("updated_at", "current_release_date"),
}


@dataclass(slots=True)
class MSRCProvider:
    key: str = "msrc"
    source_url: str = SOURCE_URL
    default_mongo_collection: str = DEFAULT_COLLECTION
    content_type: str = "json"
    list_content_type: str = "html"
    default_request_delay: float = 0.5
    stop_on_first_known: bool = False
    catch_up_full_feed: bool = True
    sync_discovery_version: str = "rss-v1"
    _client: Any = field(default=None, init=False, repr=False)
    _documents: dict[str, Any] = field(default_factory=dict, init=False, repr=False)

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return LIST_URL

    def detail_url(self, identity_display: str) -> str:
        update_id = identity_display.removeprefix("MSRC-").strip()
        if not update_id:
            raise ValueError(f"invalid MSRC update identifier: {identity_display!r}")
        if re.fullmatch(r"(?:CVE-)?\d{4}-\d{4,}", update_id):
            return f"{UPDATES_URL}/CVE-{update_id.removeprefix('CVE-')}"
        return f"{DETAIL_URL}/{quote(update_id, safe='')}"

    def detail_url_for_entry(self, entry: ListEntry) -> str | None:
        embedded_detail = getattr(entry, "embedded_detail", None)
        if isinstance(embedded_detail, dict):
            cvrf_url = embedded_detail.get("cvrf_url")
            if cvrf_url:
                return str(cvrf_url)
        return self.detail_url(getattr(entry, "display_id"))

    def request_headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    def parse_list(self, xml: str, *, page: int) -> ListPage:
        return parse_rss_list(xml, page=page, provider=self.key, source_url=self.source_url)

    def parse_detail(self, data: Any) -> MSRCMonthlyRecord:
        return parse_cvrf_document(data)

    async def enrich_detail(self, client: Any, detail: dict[str, Any], *, entry: ListEntry,
                            detail_url: str) -> dict[str, Any]:
        if not re.fullmatch(r"\d{4}-\d{4,}", entry.identity.code):
            return detail  # Saved monthly work from before RSS remains readable.
        updates = parse_update_list(detail, page=1).entries
        if not updates:
            raise ValueError(f"MSRC returned no CVRF document for {entry.key}")
        updates.sort(key=lambda update: parse_timestamp((update.embedded_detail or {}).get("current_release_date"))
                     or datetime.min.replace(tzinfo=UTC), reverse=True)
        if self._client is not client:
            self._client = client
            self._documents.clear()
        documents = []
        for update in updates:
            url = self.detail_url_for_entry(update)
            parsed = urlsplit(url or "")
            if (parsed.scheme != "https" or parsed.netloc != "api.msrc.microsoft.com"
                    or not re.fullmatch(r"/cvrf/(?:v3\.0/cvrf/)?\d{4}-[A-Za-z]{3}", parsed.path)):
                raise ValueError("MSRC returned an invalid CVRF document URL")
            if url not in self._documents:
                self._documents[url] = asyncio.create_task(client.get_json(url, headers=self.request_headers()))
            try:
                result = await self._documents[url]
            except Exception:
                self._documents.pop(url, None)
                raise
            document = self.parse_detail(result.data).to_dict()
            if not isinstance(document.get("Vulnerability"), list):
                raise ValueError("MSRC CVRF document is missing its vulnerabilities")
            documents.append({"entry": update, "document": document, "url": url})
        return {"_rss_documents": documents}

    def expand_detail_records(
        self,
        entry: ListEntry,
        detail: dict[str, Any],
        *,
        detail_url: str | None,
    ) -> list[dict[str, Any]]:
        if "_rss_documents" not in detail:
            return expand_cvrf_document(entry, detail, detail_url=detail_url, provider=self.key)
        matches = []
        listing = entry.embedded_detail or {}
        for item in detail["_rss_documents"]:
            document = item["document"]
            selected = [vulnerability for vulnerability in document["Vulnerability"]
                        if isinstance(vulnerability, dict)
                        and vulnerability.get("CVE") == f"CVE-{entry.identity.code}"]
            records = expand_cvrf_document(item["entry"], {**document, "Vulnerability": selected},
                                           detail_url=item["url"], provider=self.key)
            for record in records:
                if record["code"] != entry.identity.code:
                    continue
                record["details"][self.key]["updated_at"] = listing.get("updated_at")
                record["source"]["detail_url"] = listing.get("detail_url") or detail_url
                matches.append(record)
        if not matches:
            raise ValueError(f"MSRC CVRF documents do not contain {entry.key}")
        return [matches[0]]
