from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .browser import BrowserHTMLFetcher
from .client import FetchResult, ScraperClient, FetchError, looks_like_captcha_gate, looks_like_waf_challenge
from .config import ScraperSettings, error_log_path_for_settings
from .error_log import ScraperErrorLog, install_run_log_handler
from .models import ListEntry
from .mongo import (
    MongoClientFactory,
    MongoSyncResult,
    build_mongo_document,
    collection_from_settings,
    documents_content_match,
    existing_documents_by_id,
    existing_identity_keys,
    sync_records_to_collection,
)
from .scrapers import ScraperProvider
from .table_extractor import extract_raw_tables
from .timestamps import record_updated_at_or_after

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class Checkpoint:
    completed_identity_keys: set[str] = field(default_factory=set)
    last_list_page: int = 0
    total_pages: int | None = None
    total_records: int | None = None
    failed: dict[str, dict[str, Any]] = field(default_factory=dict)
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Checkpoint":
        if not path.exists():
            return cls()

        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return cls()
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("checkpoint JSON must be an object")
        failed_items = data.get("failed", [])
        failed = {
            item["identity"]: item
            for item in failed_items
            if isinstance(item, dict) and item.get("identity")
        }
        raw_providers = data.get("providers", {})
        providers = {
            str(key): dict(value)
            for key, value in raw_providers.items()
            if isinstance(value, dict)
        } if isinstance(raw_providers, dict) else {}
        return cls(
            completed_identity_keys=set(
                data.get("completed_identity_keys", data.get("completed_avd_ids", []))
            ),
            last_list_page=int(data.get("last_list_page", 0)),
            total_pages=data.get("total_pages"),
            total_records=data.get("total_records"),
            failed=failed,
            providers=providers,
        )

    def provider_value(self, provider: str, key: str) -> Any:
        return self.providers.get(provider, {}).get(key)

    def set_provider_value(self, provider: str, key: str, value: Any) -> None:
        self.providers.setdefault(provider, {})[key] = value

    def save(self, path: Path) -> None:
        payload = {
            "updated_at": datetime.now(UTC).isoformat(),
            "completed_identity_keys": sorted(self.completed_identity_keys),
            "last_list_page": self.last_list_page,
            "total_pages": self.total_pages,
            "total_records": self.total_records,
            "failed": sorted(self.failed.values(), key=lambda item: item.get("identity", "")),
            "providers": self.providers,
        }
        _write_json_atomic(path, payload)


class ScraperRunner:
    def __init__(
        self,
        settings: ScraperSettings,
        *,
        progress_callback: ProgressCallback | None = None,
        mongo_client_factory: MongoClientFactory | None = None,
        provider: ScraperProvider | None = None,
        cnvd_session: object | None = None,
        stop_on_first_known: bool | None = None,
        stop_on_unchanged_content: bool = False,
        updated_since: datetime | None = None,
    ) -> None:
        self.progress_callback = progress_callback
        self.mongo_client_factory = mongo_client_factory
        if provider is None:
            raise ValueError("provider is required")
        self.provider = provider
        self._cnvd_session = cnvd_session
        self._stop_on_first_known_override = stop_on_first_known
        self._stop_on_unchanged_content = stop_on_unchanged_content
        self._updated_since = updated_since
        self._existing_documents: dict[str, dict[str, Any]] = {}
        self.stop_reason: str | None = None
        self.settings = settings.for_provider(
            self.provider.key,
            default_collection=self.provider.default_mongo_collection,
            browser_fallback=self.provider.browser_fallback,
            default_request_delay=getattr(self.provider, "default_request_delay", None),
            default_concurrency=getattr(self.provider, "default_concurrency", None),
            manual_verification=getattr(self.provider, "manual_verification", None),
        ).normalized()
        self.checkpoint = Checkpoint.load(self.settings.checkpoint_file)
        self._prune_stale_provider_failures()
        self.run_failed: dict[str, dict[str, Any]] = {}
        self.records_by_id: dict[str, dict[str, Any]] = {}
        self.list_order: list[str] = []
        self.selected_ids: list[str] = []
        self.selection_finalized = False
        self.detail_fetch_count = 0
        self.expanded_entry_ids: dict[str, list[str]] = {}
        self.mongo_result = MongoSyncResult()
        self._cnvd_session_refreshed_urls: set[str] = set()
        self._error_log = ScraperErrorLog.for_settings(
            self.settings.data_dir,
            self.settings.error_log,
        )
        install_run_log_handler(self.settings.data_dir, self.settings.error_log)

    async def run(self) -> dict[str, Any]:
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)

        browser_fetcher = (
            BrowserHTMLFetcher(
                headless=self.settings.browser_headless,
                timeout_ms=self.settings.browser_timeout_ms,
                chrome_executable=self.settings.chrome_executable,
                user_data_dir=self.settings.browser_user_data_dir,
                manual_verification=self.settings.manual_verification,
                proxy_url=self.settings.proxy_url,
            )
            if self.settings.browser_fallback
            else None
        )

        self._emit(phase="starting")
        if self.provider.key == "cnvd":
            await self._prepare_cnvd_session()

        client_headers = None
        request_headers = getattr(self.provider, "request_headers", None)
        if request_headers is not None:
            client_headers = request_headers()

        client_kwargs = {
            "delay": self.settings.request_delay,
            "retries": self.settings.retries,
            "backoff_base": self.settings.backoff_base,
            "backoff_max": self.settings.backoff_max,
            "backoff_jitter": self.settings.backoff_jitter,
            "timeout": self.settings.timeout,
            "headers": client_headers,
            "proxy": self.settings.proxy_url,
        }
        if browser_fetcher is None:
            async with ScraperClient(**client_kwargs) as client:
                self._inject_cnvd_cookies(client)
                return await self._finalize_run_output(await self._run_with_client(client))

        async with browser_fetcher:
            async with ScraperClient(browser_fetcher=browser_fetcher, **client_kwargs) as client:
                self._inject_cnvd_cookies(client)
                return await self._finalize_run_output(await self._run_with_client(client))

    async def _run_with_client(self, client: ScraperClient) -> dict[str, Any]:
        if self.settings.mongo_enabled:
            return await self._run_mongo_update_with_client(client)

        await self._scrape_matching_records(client)
        output = self._build_output()
        _write_json_atomic(self.settings.output_file, output)
        self.checkpoint.save(self.settings.checkpoint_file)
        self._emit(phase="completed")
        return output

    async def _run_mongo_update_with_client(self, client: ScraperClient) -> dict[str, Any]:
        mongo_client, collection = collection_from_settings(
            self.settings,
            client_factory=self.mongo_client_factory,
        )
        try:
            if self._stop_on_unchanged_content:
                self._existing_documents = existing_documents_by_id(collection)
                known_ids = set(self._existing_documents)
            else:
                self._existing_documents = {}
                known_ids = existing_identity_keys(collection)
            await self._scrape_newest_records(client, known_ids=known_ids)
            output = self._build_output()
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="mongo")
            scraped_at = output["scraped_at"]
            self.mongo_result = sync_records_to_collection(
                output["vulnerabilities"],
                self.settings,
                collection,
                scraped_at=scraped_at,
                source={"provider": self.provider.key, "url": self.provider.source_url},
            )
            output["mongo_sync"] = self.mongo_result.to_dict()
            self._emit(phase="mongo-complete", mongo_sync=output["mongo_sync"])
            self._emit(phase="completed")
            return output
        finally:
            close = getattr(mongo_client, "close", None)
            if close is not None:
                close()

    async def _scrape_newest_records(self, client: ScraperClient, *, known_ids: set[str]) -> None:
        if self._updated_since is not None:
            await self._scrape_updated_since_records(client)
            return
        if self._stop_on_unchanged_content:
            await self._scrape_newest_records_compare_content(client, known_ids=known_ids)
            return

        self.stop_reason = None
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []
        pages_without_new = 0

        while len(selected_ids) < self.settings.limit:
            if total_pages is not None and page > total_pages:
                self.stop_reason = "limit"
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching newest-update list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure(self._list_failure_identity(), url, exc, phase="list")
                self.stop_reason = "error"
                break

            if not list_page.entries:
                self._record_failure(self._list_page_failure_identity(page), url, "No rows parsed", phase="list")
                self.stop_reason = "no_rows"
                break

            self._clear_list_failures(page=page)
            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            page_ids = [entry.key for entry in list_page.entries]
            all_known_on_page = bool(page_ids) and all(identity in known_ids for identity in page_ids)
            candidates, hit_overlap_boundary = self._newest_update_targets_for_page(
                list_page.entries,
                known_ids=known_ids,
                selected_count=len(selected_ids),
            )
            await self._fetch_details_for_page(client, candidates, len(selected_ids))

            for entry in candidates:
                for record_id in self._record_ids_for_entry(entry):
                    if record_id in selected_ids:
                        continue
                    record = self.records_by_id.get(record_id)
                    if record:
                        selected_ids.append(record_id)
                        if len(selected_ids) >= self.settings.limit:
                            self.stop_reason = "limit"
                            break
                if len(selected_ids) >= self.settings.limit:
                    break

            self.selected_ids = selected_ids.copy()
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if hit_overlap_boundary:
                self.stop_reason = "overlap"
                break
            if all_known_on_page and not candidates:
                if self._stop_on_first_known():
                    pages_without_new += 1
                    if pages_without_new >= 2:
                        self.stop_reason = "overlap"
                        break
                elif page == 1 and total_pages == 2 and not selected_ids:
                    # Heuristic: when there's only a single "older" page, and the
                    # newest page is fully known, stop to avoid overlap churn.
                    self.stop_reason = "overlap"
                    break
                page += 1
                continue
            pages_without_new = 0
            page += 1

        if self.stop_reason is None and len(selected_ids) >= self.settings.limit:
            self.stop_reason = "limit"

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    async def _scrape_updated_since_records(self, client: ScraperClient) -> None:
        if self._updated_since is None:
            raise ValueError("updated-since scrape requires a timestamp boundary")

        self.stop_reason = None
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if total_pages is not None and page > total_pages:
                self.stop_reason = "timestamp_boundary"
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching updated-since list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure(self._list_failure_identity(), url, exc, phase="list")
                self.stop_reason = "error"
                break

            if not list_page.entries:
                self._record_failure(self._list_page_failure_identity(page), url, "No rows parsed", phase="list")
                self.stop_reason = "no_rows"
                break

            self._clear_list_failures(page=page)
            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            page_has_parseable_timestamps = False
            hit_timestamp_boundary = False
            for entry in list_page.entries:
                if self._detail_url_for_entry(entry) is not None and not self._has_detail(entry.key):
                    await self._scrape_detail(client, entry)

                for record_id in self._record_ids_for_entry(entry):
                    record = self.records_by_id.get(record_id)
                    if not record:
                        continue
                    comparison = record_updated_at_or_after(record, self._updated_since)
                    if comparison is None:
                        continue
                    page_has_parseable_timestamps = True
                    if not comparison:
                        hit_timestamp_boundary = True
                        self.stop_reason = "timestamp_boundary"
                        break
                    if record_id not in selected_ids:
                        selected_ids.append(record_id)
                    if len(selected_ids) >= self.settings.limit:
                        self.stop_reason = "limit"
                        break
                if self.stop_reason in {"limit", "timestamp_boundary"}:
                    break

            self.selected_ids = selected_ids.copy()
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)

            if self.stop_reason in {"limit", "timestamp_boundary"}:
                break
            if not page_has_parseable_timestamps or hit_timestamp_boundary:
                self.stop_reason = "timestamp_boundary"
                break
            page += 1

        if self.stop_reason is None:
            self.stop_reason = "timestamp_boundary"

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    async def _scrape_newest_records_compare_content(
        self,
        client: ScraperClient,
        *,
        known_ids: set[str],
    ) -> None:
        self.stop_reason = None
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if total_pages is not None and page > total_pages:
                self.stop_reason = "limit"
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching newest-update list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure(self._list_failure_identity(), url, exc, phase="list")
                self.stop_reason = "error"
                break

            if not list_page.entries:
                self._record_failure(self._list_page_failure_identity(page), url, "No rows parsed", phase="list")
                self.stop_reason = "no_rows"
                break

            self._clear_list_failures(page=page)
            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            for entry in list_page.entries:
                if len(selected_ids) >= self.settings.limit:
                    self.stop_reason = "limit"
                    break

                if self._detail_url_for_entry(entry) is not None and not self._has_detail(entry.key):
                    await self._scrape_detail(client, entry)

                entry_record_ids = self._record_ids_for_entry(entry)
                record = self.records_by_id.get(entry_record_ids[0]) if entry_record_ids else None
                if not record:
                    continue

                if entry.key in known_ids:
                    if self._record_matches_existing_mongo(record):
                        self.stop_reason = "overlap"
                        break
                    self._existing_documents[entry.key] = build_mongo_document(
                        record,
                        self._mongo_compare_output(),
                    )

                for record_id in entry_record_ids:
                    if record_id not in selected_ids and self.records_by_id.get(record_id):
                        selected_ids.append(record_id)
                        if len(selected_ids) >= self.settings.limit:
                            self.stop_reason = "limit"
                            break

            self.selected_ids = selected_ids.copy()
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if self.stop_reason in {"overlap", "limit"}:
                break
            page += 1

        if self.stop_reason is None and len(selected_ids) >= self.settings.limit:
            self.stop_reason = "limit"

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    def _should_refresh_existing_before_stop(self) -> bool:
        return self.settings.mongo_conflict == "overwrite" or (
            self.settings.mongo_conflict == "prompt" and self.settings.mongo_interactive
        )

    def _newest_update_targets_for_page(
        self,
        entries: list[ListEntry],
        *,
        known_ids: set[str],
        selected_count: int,
    ) -> tuple[list[ListEntry], bool]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []
        refresh_existing = self._should_refresh_existing_before_stop()
        stop_on_first_known = self._stop_on_first_known() and not refresh_existing
        saw_new = False
        hit_overlap_boundary = False
        for entry in entries:
            if remaining <= 0:
                break
            if entry.key in known_ids and not refresh_existing:
                if stop_on_first_known and saw_new:
                    hit_overlap_boundary = True
                    break
                continue
            targets.append(entry)
            remaining -= 1
            saw_new = True
        return targets, hit_overlap_boundary

    def _mongo_compare_output(self) -> dict[str, Any]:
        return {
            "scraped_at": datetime.now(UTC).isoformat(),
            "source": {"provider": self.provider.key, "url": self.provider.source_url},
        }

    def _record_matches_existing_mongo(self, record: dict[str, Any]) -> bool:
        if not self._stop_on_unchanged_content:
            return False
        id_type = str(record.get("type") or "").strip().lower()
        code = str(record.get("code") or "").strip()
        if not id_type or not code:
            return False
        key = f"{id_type}:{code}"
        existing = self._existing_documents.get(key)
        if existing is None:
            return False
        document = build_mongo_document(record, self._mongo_compare_output())
        return documents_content_match(existing, document)

    def _stop_on_first_known(self) -> bool:
        if self._stop_on_first_known_override is not None:
            return self._stop_on_first_known_override
        return bool(getattr(self.provider, "stop_on_first_known", False))

    def _always_use_browser(self) -> bool:
        return bool(getattr(self.provider, "always_use_browser", False))

    def _uses_cnvd_session(self) -> bool:
        return self.provider.key == "cnvd" and self._cnvd_session is not None

    async def _prepare_cnvd_session(self) -> None:
        from .scrapers.cnvd.session import CNVDSession, CNVDSessionError

        self._cnvd_session_refreshed_urls.clear()
        session = self._cnvd_session
        if session is None:
            session = CNVDSession.for_data_dir(
                self.settings.data_dir,
                max_retries=self.settings.session_max_retries or 50,
                retry_delay=self.settings.session_retry_delay or 0.3,
                proxy_url=self.settings.proxy_url,
            )
            self._cnvd_session = session

        if getattr(session, "is_authenticated", False):
            logger.info("Using pre-authenticated CNVD session (%d cookies)", len(session.cookies_for_httpx()))
            return

        logger.info("Refreshing CNVD session cookies before scrape")
        try:
            await asyncio.to_thread(
                session.ensure_authenticated,
                refresh_cookies=True,
                persist_cookies=False,
            )
        except CNVDSessionError as exc:
            raise FetchError(str(exc)) from exc

    def _inject_cnvd_cookies(self, client: ScraperClient) -> None:
        if not self._uses_cnvd_session():
            return
        cookies = self._cnvd_session.cookies_for_httpx()  # type: ignore[union-attr]
        client.inject_cookies(cookies)

    async def _refresh_cnvd_session(self, client: ScraperClient, url: str) -> None:
        if url in self._cnvd_session_refreshed_urls or not self._uses_cnvd_session():
            return
        self._cnvd_session_refreshed_urls.add(url)
        logger.info("Refreshing CNVD session cookies after gate response for %s", url)
        await asyncio.to_thread(
            self._cnvd_session.ensure_authenticated,  # type: ignore[union-attr]
            refresh_cookies=True,
            persist_cookies=False,
        )
        self._inject_cnvd_cookies(client)

    @staticmethod
    def _cnvd_html_blocked(html: str) -> bool:
        return looks_like_captcha_gate(html) or looks_like_waf_challenge(html)

    async def _fetch_cnvd_html(self, client: ScraperClient, url: str) -> Any:
        result = await client.get_html(url)
        if not self._cnvd_html_blocked(result.html):
            return result
        await self._refresh_cnvd_session(client, url)
        result = await client.get_html(url)
        if self._cnvd_html_blocked(result.html):
            raise FetchError(f"CNVD gate blocked content for {url}")
        return result

    async def _fetch_provider_html(self, client: ScraperClient, url: str) -> Any:
        if self._uses_cnvd_session():
            return await self._fetch_cnvd_html(client, url)
        if self.provider.key == "avd":
            return await self._fetch_avd_html(client, url)
        if self._always_use_browser():
            return await client.get_html(url, force_browser=True)
        return await client.get_html(url)

    @staticmethod
    def _client_cookies_snapshot(client: ScraperClient) -> list[dict[str, Any]]:
        cookies: list[dict[str, Any]] = []
        for cookie in client._client.cookies.jar:
            if not cookie.name:
                continue
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path or "/",
                }
            )
        return cookies

    async def _fetch_avd_html(self, client: ScraperClient, url: str) -> FetchResult:
        import requests

        from vuln_scraper.scrapers.avd.h import AVDSigchlError, fetch_via_redirect

        await client.rate_limiter.wait()
        headers = None
        request_headers = getattr(self.provider, "request_headers", None)
        if request_headers is not None:
            headers = request_headers()

        try:
            fetch_kwargs: dict[str, Any] = {
                "headers": headers,
                "cookies": self._client_cookies_snapshot(client),
                "timeout": self.settings.timeout,
            }
            if self.settings.proxy_url:
                # Only pass proxy_url when configured; this keeps test mocks simple.
                fetch_kwargs["proxy_url"] = self.settings.proxy_url

            html, final_url, cookies = await asyncio.to_thread(
                fetch_via_redirect,
                url,
                **fetch_kwargs,
            )
            client.inject_cookies(cookies)
            if looks_like_waf_challenge(html) and "<table" not in html.lower():
                logger.info("AVD redirect fetch still blocked for %s; using browser fallback", url)
                return await client.get_html(url)
            return FetchResult(html=html, status_code=200, url=final_url)
        except ImportError as exc:
            logger.warning("AVD sigchl unavailable (%s); using standard fetch for %s", exc, url)
            return await client.get_html(url)
        except AVDSigchlError as exc:
            logger.warning("AVD sigchl solve failed for %s: %s", url, exc)
            return await client.get_html(url)
        except requests.RequestException as exc:
            logger.warning("AVD redirect fetch failed for %s: %s; using standard fetch", url, exc)
            return await client.get_html(url)

    async def _scrape_matching_records(self, client: ScraperClient) -> None:
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if total_pages is not None and page > total_pages:
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure(self._list_failure_identity(), url, exc, phase="list")
                break

            if not list_page.entries:
                self._record_failure(self._list_page_failure_identity(page), url, "No rows parsed", phase="list")
                break

            self._clear_list_failures(page=page)
            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            await self._fetch_details_for_page(client, list_page.entries, len(selected_ids))

            for entry in list_page.entries:
                for record_id in self._record_ids_for_entry(entry):
                    if record_id in selected_ids:
                        continue
                    record = self.records_by_id.get(record_id)
                    if record:
                        selected_ids.append(record_id)
                        if len(selected_ids) >= self.settings.limit:
                            break
                if len(selected_ids) >= self.settings.limit:
                    break

            self.selected_ids = selected_ids.copy()
            _write_json_atomic(self.settings.output_file, self._build_output())
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            page += 1

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    async def _fetch_details_for_page(
        self,
        client: ScraperClient,
        entries: list[ListEntry],
        selected_count: int,
        *,
        ignore_limit: bool = False,
    ) -> None:
        targets = self._detail_targets_for_page(entries, selected_count, ignore_limit=ignore_limit)
        if not targets:
            logger.info("No detail pages to fetch for this page.")
            return

        semaphore = asyncio.Semaphore(max(1, self.settings.concurrency))

        async def scrape_one(entry: ListEntry) -> None:
            async with semaphore:
                await self._scrape_detail(client, entry)

        await asyncio.gather(*(scrape_one(entry) for entry in targets))

    async def _fetch_list_page(self, client: ScraperClient, url: str, page: int) -> Any:
        if getattr(self.provider, "content_type", "html") == "json":
            request_factory = getattr(self.provider, "list_json_request", None)
            if request_factory is not None:
                request = request_factory(page, checkpoint=self.checkpoint)
                result = await self._fetch_json_request(client, request)
            else:
                headers = await self._provider_request_headers()
                request_method = str(getattr(self.provider, "request_method", "GET")).upper()
                if request_method == "POST":
                    payload_factory = getattr(self.provider, "request_payload", None)
                    payload = payload_factory(page) if callable(payload_factory) else None
                    result = await client.post_json(url, json=payload, headers=headers)
                else:
                    result = await client.get_json(url, headers=headers)
            parse_kwargs: dict[str, Any] = {"page": page}
            if self.provider.key == "cve" and self._updated_since is not None:
                parse_kwargs["updated_since"] = self._updated_since
            return self.provider.parse_list(result.data, **parse_kwargs)

        result = await self._fetch_provider_html(client, url)
        return self.provider.parse_list(result.html, page=page)

    async def _fetch_json_request(self, client: ScraperClient, request: dict[str, Any]) -> Any:
        method = str(request.get("method") or "GET")
        url = str(request.get("url") or "")
        if not url:
            raise FetchError("provider JSON request did not include a URL")
        headers = dict(request.get("headers") or {})
        if method.upper() == "GET" and "json" not in request and "data" not in request:
            return await client.get_json(url, headers=headers)
        return await client.request_json(
            method,
            url,
            headers=headers,
            json_body=request.get("json"),
            data=request.get("data"),
        )

    async def _provider_request_headers(self) -> dict[str, str]:
        async_request_headers = getattr(self.provider, "async_request_headers", None)
        if async_request_headers is not None:
            try:
                headers = async_request_headers()
                if inspect.isawaitable(headers):
                    headers = await headers
            except Exception as exc:
                raise FetchError(str(exc)) from exc
            return dict(headers)

        request_headers = getattr(self.provider, "request_headers", None)
        if request_headers is None:
            return {}
        try:
            return dict(request_headers())
        except Exception as exc:
            raise FetchError(str(exc)) from exc

    def _detail_targets_for_page(
        self,
        entries: list[ListEntry],
        selected_count: int,
        *,
        ignore_limit: bool = False,
    ) -> list[ListEntry]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []

        for entry in entries:
            if remaining <= 0 and not ignore_limit:
                break
            if not self._has_detail(entry.key):
                if self._detail_url_for_entry(entry) is None:
                    continue
                targets.append(entry)
                self.detail_fetch_count += 1
            if not ignore_limit:
                remaining -= 1

        return targets

    async def _scrape_detail(self, client: ScraperClient, entry: ListEntry) -> None:
        url = self._detail_url_for_entry(entry)
        if url is None:
            self.records_by_id[entry.key] = entry.to_record(entry.embedded_detail, detail_url=None)
            return
        logger.info("Fetching detail %s", entry.key)
        self._emit(phase="detail", identity=entry.key, type=entry.identity.type, code=entry.identity.code)
        try:
            if getattr(self.provider, "content_type", "html") == "json":
                result, detail = await self._fetch_json_detail(client, entry, url)
                raw_detail_content = result.data
            else:
                result = await self._fetch_provider_html(client, url)
                raw_detail_content = result.html
                detail = self.provider.parse_detail(result.html).to_dict()
            finalize_detail = getattr(self.provider, "finalize_detail", None)
            if finalize_detail is not None:
                detail = finalize_detail(detail, entry=entry, detail_url=url)
            expand_detail_records = getattr(self.provider, "expand_detail_records", None)
            if expand_detail_records is not None:
                expanded_records = list(expand_detail_records(entry, detail, detail_url=url))
                expanded_ids: list[str] = []
                for record in expanded_records:
                    record_type = str(record.get("type") or "").strip().lower()
                    code = str(record.get("code") or "").strip()
                    if not record_type or not code:
                        continue
                    record_id = f"{record_type}:{code}"
                    if record_id not in self.records_by_id:
                        self.records_by_id[record_id] = record
                    if record_id not in self.list_order:
                        self.list_order.append(record_id)
                    expanded_ids.append(record_id)
                    self.checkpoint.completed_identity_keys.add(record_id)
                    self.checkpoint.failed.pop(record_id, None)
                self.expanded_entry_ids[entry.key] = expanded_ids
                if expanded_ids:
                    self.checkpoint.completed_identity_keys.add(entry.key)
                    self.checkpoint.failed.pop(entry.key, None)
                    return
            raw_tables = extract_raw_tables(raw_detail_content)
            if raw_tables:
                detail["raw_tables"] = raw_tables
            self.records_by_id[entry.key] = entry.to_record(detail, detail_url=url)
            self.checkpoint.completed_identity_keys.add(entry.key)
            self.checkpoint.failed.pop(entry.key, None)
        except Exception as exc:
            self.records_by_id[entry.key] = entry.to_record(None, detail_url=url)
            self._record_failure(entry, url, exc, phase="detail")
        finally:
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="detail-complete", identity=entry.key, type=entry.identity.type, code=entry.identity.code)

    async def _fetch_json_detail(
        self,
        client: ScraperClient,
        entry: ListEntry,
        detail_url: str,
    ) -> tuple[Any, dict[str, Any]]:
        requests_factory = getattr(self.provider, "detail_json_requests", None)
        if requests_factory is not None:
            requests = list(requests_factory(entry, detail_url=detail_url))
            if not requests:
                raise FetchError("provider JSON detail requests did not include any requests")
            last_error: Exception | None = None
            for request in requests:
                try:
                    result = await self._fetch_json_request(client, request)
                    return result, self.provider.parse_detail(result.data).to_dict()
                except Exception as exc:
                    last_error = exc
            raise FetchError(f"all provider JSON detail requests failed: {last_error}") from last_error

        request_factory = getattr(self.provider, "detail_json_request", None)
        if request_factory is not None:
            result = await self._fetch_json_request(client, request_factory(entry, detail_url=detail_url))
        else:
            result = await client.get_json(detail_url, headers=await self._provider_request_headers())
        return result, self.provider.parse_detail(result.data).to_dict()

    def _merge_list_entries(self, entries: list[ListEntry]) -> None:
        for entry in entries:
            if entry.key not in self.list_order:
                self.list_order.append(entry.key)
            existing_detail = self.records_by_id.get(entry.key, {}).get("details", {}).get(entry.provider)
            effective_detail = existing_detail if existing_detail is not None else entry.embedded_detail
            detail_url = self._detail_url_for_entry(entry)
            self.records_by_id[entry.key] = entry.to_record(effective_detail, detail_url=detail_url)

    def _build_output(self) -> dict[str, Any]:
        if self.selected_ids or self.selection_finalized:
            ordered_ids = self.selected_ids
        else:
            ordered_ids = [
                identity
                for identity in self.list_order
                if identity in self.records_by_id
            ][: self.settings.limit]
        vulnerabilities = [
            self.records_by_id[identity]
            for identity in ordered_ids[: self.settings.limit]
            if identity in self.records_by_id
        ]
        return {
            "scraped_at": datetime.now(UTC).isoformat(),
            "source": {"provider": self.provider.key, "url": self.provider.source_url},
            "total": self.checkpoint.total_records or len(self.list_order),
            "result_count": len(vulnerabilities),
            "raw_limit": self.settings.limit,
            "stop_reason": self.stop_reason,
            "failed": sorted(self.run_failed.values(), key=lambda item: item.get("identity", "")),
            "vulnerabilities": vulnerabilities,
        }

    def _list_failure_identity(self) -> str:
        return f"{self.provider.key}:LIST"

    def _list_page_failure_identity(self, page: int) -> str:
        return f"{self.provider.key}:LIST-PAGE-{page}"

    def _prune_stale_provider_failures(self) -> None:
        prefix = f"{self.provider.key}:"
        current_list_url = self.provider.list_url(1)
        for key in list(self.checkpoint.failed):
            if key.startswith(prefix):
                self.checkpoint.failed.pop(key, None)
                continue
            if key in ("LIST",) or key.startswith("LIST-PAGE-"):
                item = self.checkpoint.failed.get(key)
                if isinstance(item, dict) and item.get("url") != current_list_url:
                    self.checkpoint.failed.pop(key, None)

    def _clear_list_failures(self, *, page: int) -> None:
        self.checkpoint.failed.pop(self._list_failure_identity(), None)
        self.checkpoint.failed.pop(self._list_page_failure_identity(page), None)
        self.checkpoint.failed.pop("LIST", None)
        self.checkpoint.failed.pop(f"LIST-PAGE-{page}", None)

    def _has_detail(self, identity: str) -> bool:
        if identity in self.expanded_entry_ids:
            return bool(self.expanded_entry_ids[identity])
        details = self.records_by_id.get(identity, {}).get("details")
        detail = details.get(self.provider.key) if isinstance(details, dict) else None
        return isinstance(detail, dict) and not detail.get("_list_summary")

    def _record_ids_for_entry(self, entry: ListEntry) -> list[str]:
        expanded_ids = self.expanded_entry_ids.get(entry.key)
        if expanded_ids is not None:
            return expanded_ids
        return [entry.key]

    def _detail_url_for_entry(self, entry: ListEntry) -> str | None:
        detail_url_for_entry = getattr(self.provider, "detail_url_for_entry", None)
        if detail_url_for_entry is not None:
            return detail_url_for_entry(entry)
        return self.provider.detail_url(entry.display_id)

    def _record_failure(self, identity: str | ListEntry, url: str, error: object, *, phase: str) -> None:
        if isinstance(identity, ListEntry):
            identity_key = identity.key
            id_type = identity.identity.type
            code = identity.identity.code
        else:
            identity_key = identity
            id_type, _, code = identity.partition(":")
        message = str(error)
        logger.warning("%s failed for %s: %s", phase, identity_key, message)
        failure = {
            "identity": identity_key,
            "type": id_type,
            "code": code,
            "phase": phase,
            "url": url,
            "error": message,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        self.checkpoint.failed[identity_key] = failure
        self.run_failed[identity_key] = failure
        self._emit(phase=f"{phase}-failed", identity=identity_key, type=id_type, code=code, error=message)
        self._error_log.append(
            provider=self.provider.key,
            phase=phase,
            identity=identity_key,
            url=url,
            error=message,
        )

    async def _finalize_run_output(self, output: dict[str, Any]) -> dict[str, Any]:
        stop_reason = output.get("stop_reason")
        if stop_reason in ("error", "no_rows"):
            failed_count = len(self.run_failed)
            self._error_log.append(
                provider=self.provider.key,
                phase="run-summary",
                identity="",
                url="",
                error=f"run stopped: {stop_reason} ({failed_count} failed item(s))",
                stop_reason=stop_reason,
            )
        error_log_path = error_log_path_for_settings(self.settings)
        if error_log_path is not None:
            output["error_log"] = str(error_log_path)
        return output

    def _emit(self, **event: Any) -> None:
        if self.progress_callback is None:
            return
        payload = {
            "selected_count": len(self.selected_ids),
            "completed_count": len(self.checkpoint.completed_identity_keys),
            "failed_count": len(self.run_failed),
            **event,
        }
        self.progress_callback(payload)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    tmp_path.replace(path)
