from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .browser import BrowserHTMLFetcher
from .client import FetchResult, ScraperClient, FetchError, looks_like_captcha_gate, looks_like_waf_challenge
from .config import ScraperSettings, error_log_path_for_settings
from .error_log import ScraperErrorLog, install_run_log_handler
from .cve_backfill import backfill_missing_cves
from .models import ListEntry
from .mongo import (
    MongoClientFactory,
    MongoSyncResult,
    collection_from_settings,
    existing_identity_keys,
    sync_records_to_collection,
)
from .providers import ScraperProvider
from .scrapers.cve.config import MAX_DATE_WINDOW_DAYS

logger = logging.getLogger(__name__)

_DEBUG_LOG_PATH = Path(__file__).resolve().parents[1] / ".cursor" / "debug-120861.log"


def _agent_debug_log(
    location: str,
    message: str,
    data: dict[str, Any],
    *,
    hypothesis_id: str,
    run_id: str = "pre-fix",
) -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "120861",
            "timestamp": int(datetime.now(UTC).timestamp() * 1000),
            "location": location,
            "message": message,
            "data": data,
            "hypothesisId": hypothesis_id,
            "runId": run_id,
        }
        with _DEBUG_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError:
        pass
    # #endregion


ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class Checkpoint:
    completed_identity_keys: set[str] = field(default_factory=set)
    last_list_page: int = 0
    total_pages: int | None = None
    total_records: int | None = None
    failed: dict[str, dict[str, Any]] = field(default_factory=dict)
    nvd_last_mod_start: str | None = None
    nvd_last_mod_end: str | None = None
    nvd_start_index: int = 0

    @classmethod
    def load(cls, path: Path) -> "Checkpoint":
        if not path.exists():
            return cls()

        data = json.loads(path.read_text(encoding="utf-8"))
        failed_items = data.get("failed", [])
        failed = {
            item["identity"]: item
            for item in failed_items
            if isinstance(item, dict) and item.get("identity")
        }
        return cls(
            completed_identity_keys=set(
                data.get("completed_identity_keys", data.get("completed_avd_ids", []))
            ),
            last_list_page=int(data.get("last_list_page", 0)),
            total_pages=data.get("total_pages"),
            total_records=data.get("total_records"),
            failed=failed,
            nvd_last_mod_start=data.get("nvd_last_mod_start"),
            nvd_last_mod_end=data.get("nvd_last_mod_end"),
            nvd_start_index=int(data.get("nvd_start_index", 0)),
        )

    def save(self, path: Path) -> None:
        payload = {
            "updated_at": datetime.now(UTC).isoformat(),
            "completed_identity_keys": sorted(self.completed_identity_keys),
            "last_list_page": self.last_list_page,
            "total_pages": self.total_pages,
            "total_records": self.total_records,
            "nvd_last_mod_start": self.nvd_last_mod_start,
            "nvd_last_mod_end": self.nvd_last_mod_end,
            "nvd_start_index": self.nvd_start_index,
            "failed": sorted(self.failed.values(), key=lambda item: item.get("identity", "")),
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
    ) -> None:
        self.progress_callback = progress_callback
        self.mongo_client_factory = mongo_client_factory
        if provider is None:
            raise ValueError("provider is required")
        self.provider = provider
        self._cnvd_session = cnvd_session
        self._stop_on_first_known_override = stop_on_first_known
        self.stop_reason: str | None = None
        self.settings = settings.for_provider(
            self.provider.key,
            default_collection=self.provider.default_mongo_collection,
            browser_fallback=self.provider.browser_fallback,
            default_request_delay=getattr(self.provider, "default_request_delay", None),
            default_concurrency=getattr(self.provider, "default_concurrency", None),
            manual_verification=getattr(self.provider, "manual_verification", None),
        ).normalized()
        self.checkpoint = Checkpoint()
        self.records_by_id: dict[str, dict[str, Any]] = {}
        self.list_order: list[str] = []
        self.selected_ids: list[str] = []
        self.selection_finalized = False
        self.detail_fetch_count = 0
        self.mongo_result = MongoSyncResult()
        self._cnvd_session_refreshed_urls: set[str] = set()
        self._error_log = ScraperErrorLog.for_settings(
            self.settings.data_dir,
            self.settings.error_log,
        )
        install_run_log_handler(self.settings.data_dir, self.settings.error_log)

    async def run(self) -> dict[str, Any]:
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)

        if self.settings.resume:
            self.checkpoint = Checkpoint.load(self.settings.checkpoint_file)
            self.records_by_id, self.list_order = _load_existing_output(self.settings.output_file)

        browser_fetcher = (
            BrowserHTMLFetcher(
                headless=self.settings.browser_headless,
                timeout_ms=self.settings.browser_timeout_ms,
                chrome_executable=self.settings.chrome_executable,
                user_data_dir=self.settings.browser_user_data_dir,
                manual_verification=self.settings.manual_verification,
                data_dir=self.settings.data_dir,
                browser_gate_url=getattr(self.provider, "browser_gate_url", None),
                captcha_update_selector=getattr(
                    self.provider,
                    "captcha_update_selector",
                    "#update",
                ),
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
        self._ensure_provider_checkpoint()
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
            if self.provider.key != "cve":
                backfill_result = await backfill_missing_cves(
                    output["vulnerabilities"],
                    self.settings,
                    mongo_client,
                    scraped_at=scraped_at,
                )
                if (
                    backfill_result.inserted
                    or backfill_result.overwritten
                    or backfill_result.skipped
                    or backfill_result.conflicts
                    or backfill_result.errors
                ):
                    output["cve_backfill"] = backfill_result.to_dict()
            self._emit(phase="mongo-complete", mongo_sync=output["mongo_sync"])
            self._emit(phase="completed")
            return output
        finally:
            close = getattr(mongo_client, "close", None)
            if close is not None:
                close()

    async def _scrape_newest_records(self, client: ScraperClient, *, known_ids: set[str]) -> None:
        self.stop_reason = None
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if self.settings.max_pages is not None and page > self.settings.max_pages:
                self.stop_reason = "limit"
                break
            if total_pages is not None and page > total_pages:
                self.stop_reason = "limit"
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching newest-update list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure("LIST", url, exc, phase="list")
                self.stop_reason = "error"
                break

            if not list_page.entries:
                if self._empty_nvd_window_complete(list_page):
                    self._complete_nvd_window()
                    self.stop_reason = "nvd_window_complete"
                    break
                self._record_failure(f"LIST-PAGE-{page}", url, "No rows parsed", phase="list")
                self.stop_reason = "no_rows"
                break

            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            page_ids = [entry.key for entry in list_page.entries]
            all_known_on_page = (
                self.provider.key != "cve"
                and bool(page_ids)
                and all(identity in known_ids for identity in page_ids)
            )
            stop_at_known_on_page = (
                self._stop_on_first_known()
                and not self._should_refresh_existing_before_stop()
                and any(identity in known_ids for identity in page_ids)
            )
            candidates = self._newest_update_targets_for_page(
                list_page.entries,
                known_ids=known_ids,
                selected_count=len(selected_ids),
            )
            await self._fetch_details_for_page(client, candidates, len(selected_ids))

            for entry in candidates:
                if entry.key in selected_ids:
                    continue
                record = self.records_by_id.get(entry.key)
                if record:
                    selected_ids.append(entry.key)
                    if len(selected_ids) >= self.settings.limit:
                        self.stop_reason = "limit"
                        break

            self.selected_ids = selected_ids.copy()
            self._advance_nvd_checkpoint(list_page)
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if self._nvd_window_page_complete(list_page):
                self._complete_nvd_window()
                self.checkpoint.save(self.settings.checkpoint_file)
                self.stop_reason = "nvd_window_complete"
                break
            if all_known_on_page or stop_at_known_on_page:
                self.stop_reason = "overlap"
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
    ) -> list[ListEntry]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []
        refresh_existing = self._should_refresh_existing_before_stop()
        stop_on_first_known = self._stop_on_first_known() and not refresh_existing
        saw_new = False
        for entry in entries:
            if remaining <= 0:
                break
            if self.provider.key != "cve" and entry.key in known_ids and not refresh_existing:
                if stop_on_first_known and saw_new:
                    break
                continue
            targets.append(entry)
            remaining -= 1
            saw_new = True
        return targets

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
        from vuln_scraper.scrapers.avd.h import AVDSigchlError, fetch_via_redirect

        await client.rate_limiter.wait()
        headers = None
        request_headers = getattr(self.provider, "request_headers", None)
        if request_headers is not None:
            headers = request_headers()

        try:
            html, final_url, cookies = await asyncio.to_thread(
                fetch_via_redirect,
                url,
                headers=headers,
                cookies=self._client_cookies_snapshot(client),
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

    async def _scrape_matching_records(self, client: ScraperClient) -> None:
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if self.settings.max_pages is not None and page > self.settings.max_pages:
                break
            if total_pages is not None and page > total_pages:
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure("LIST", url, exc, phase="list")
                break

            if not list_page.entries:
                if self._empty_nvd_window_complete(list_page):
                    self._complete_nvd_window()
                    break
                self._record_failure(f"LIST-PAGE-{page}", url, "No rows parsed", phase="list")
                break

            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            await self._fetch_details_for_page(client, list_page.entries, len(selected_ids))

            for entry in list_page.entries:
                if entry.key in selected_ids:
                    continue
                record = self.records_by_id.get(entry.key)
                if record:
                    selected_ids.append(entry.key)
                    if len(selected_ids) >= self.settings.limit:
                        break

            self.selected_ids = selected_ids.copy()
            self._advance_nvd_checkpoint(list_page)
            _write_json_atomic(self.settings.output_file, self._build_output())
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if self._nvd_window_page_complete(list_page):
                self._complete_nvd_window()
                self.checkpoint.save(self.settings.checkpoint_file)
                break
            page += 1

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    async def _fetch_details_for_page(
        self,
        client: ScraperClient,
        entries: list[ListEntry],
        selected_count: int,
    ) -> None:
        if self.settings.list_only:
            return

        targets = self._detail_targets_for_page(entries, selected_count)
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
            return self.provider.parse_list(result.data, page=page)

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

    def _ensure_provider_checkpoint(self) -> None:
        if self.provider.key != "cve":
            return
        if self.checkpoint.nvd_last_mod_start and self.checkpoint.nvd_last_mod_end:
            return

        now = datetime.now(UTC)
        if self.checkpoint.nvd_last_mod_start:
            start = _parse_nvd_datetime(self.checkpoint.nvd_last_mod_start)
            max_end = start + timedelta(days=MAX_DATE_WINDOW_DAYS)
            end = min(now, max_end)
        else:
            start = now - timedelta(days=MAX_DATE_WINDOW_DAYS)
            end = now

        self.checkpoint.nvd_last_mod_start = _format_nvd_datetime(start)
        self.checkpoint.nvd_last_mod_end = _format_nvd_datetime(end)
        self.checkpoint.nvd_start_index = max(0, self.checkpoint.nvd_start_index)

    def _advance_nvd_checkpoint(self, list_page: Any) -> None:
        if self.provider.key != "cve":
            return
        start_index = list_page.start_index if list_page.start_index is not None else self.checkpoint.nvd_start_index
        page_size = list_page.results_per_page or len(list_page.entries)
        self.checkpoint.nvd_start_index = max(self.checkpoint.nvd_start_index, start_index + page_size)

    def _nvd_window_page_complete(self, list_page: Any) -> bool:
        if self.provider.key != "cve" or list_page.total_records is None:
            return False
        return self.checkpoint.nvd_start_index >= list_page.total_records

    def _empty_nvd_window_complete(self, list_page: Any) -> bool:
        return self.provider.key == "cve" and (list_page.total_records or 0) == 0

    def _complete_nvd_window(self) -> None:
        if self.provider.key != "cve":
            return
        self.checkpoint.nvd_last_mod_start = self.checkpoint.nvd_last_mod_end
        self.checkpoint.nvd_last_mod_end = None
        self.checkpoint.nvd_start_index = 0

    def _detail_targets_for_page(
        self,
        entries: list[ListEntry],
        selected_count: int,
    ) -> list[ListEntry]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []

        for entry in entries:
            if remaining <= 0:
                break

            # #region agent log
            _agent_debug_log(
                "runner.py:_detail_targets_for_page",
                "detail target check",
                {
                    "entry_key": entry.key,
                    "has_detail": self._has_detail(entry.key),
                    "embedded_keys": list((entry.embedded_detail or {}).keys())
                    if isinstance(entry.embedded_detail, dict)
                    else [],
                },
                hypothesis_id="A",
            )
            # #endregion
            if not self._has_detail(entry.key):
                if self._detail_url_for_entry(entry) is None:
                    continue
                if self.settings.max_details is not None and self.detail_fetch_count >= self.settings.max_details:
                    break
                targets.append(entry)
                self.detail_fetch_count += 1
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
                request_factory = getattr(self.provider, "detail_json_request", None)
                if request_factory is not None:
                    request = request_factory(entry, detail_url=url)
                    result = await self._fetch_json_request(client, request)
                else:
                    result = await client.get_json(url, headers=await self._provider_request_headers())
                detail = self.provider.parse_detail(result.data).to_dict()
            else:
                result = await self._fetch_provider_html(client, url)
                detail = self.provider.parse_detail(result.html).to_dict()
            # #region agent log
            _agent_debug_log(
                "runner.py:_scrape_detail",
                "parsed detail fields",
                {
                    "entry_key": entry.key,
                    "detail_keys": sorted(detail.keys()) if isinstance(detail, dict) else [],
                    "has_cve_id": bool((detail or {}).get("cve_id")),
                    "has_description": bool((detail or {}).get("description")),
                },
                hypothesis_id="C",
            )
            # #endregion
            finalize_detail = getattr(self.provider, "finalize_detail", None)
            if finalize_detail is not None:
                detail = finalize_detail(detail, entry=entry, detail_url=url)
            self.records_by_id[entry.key] = entry.to_record(detail, detail_url=url)
            self.checkpoint.completed_identity_keys.add(entry.key)
            self.checkpoint.failed.pop(entry.key, None)
        except Exception as exc:
            self.records_by_id[entry.key] = entry.to_record(None, detail_url=url)
            self._record_failure(entry, url, exc, phase="detail")
        finally:
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="detail-complete", identity=entry.key, type=entry.identity.type, code=entry.identity.code)

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
            "failed": sorted(self.checkpoint.failed.values(), key=lambda item: item.get("identity", "")),
            "vulnerabilities": vulnerabilities,
        }

    def _has_detail(self, identity: str) -> bool:
        details = self.records_by_id.get(identity, {}).get("details")
        detail = details.get(self.provider.key) if isinstance(details, dict) else None
        return isinstance(detail, dict) and not detail.get("_list_summary")

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
        self.checkpoint.failed[identity_key] = {
            "identity": identity_key,
            "type": id_type,
            "code": code,
            "phase": phase,
            "url": url,
            "error": message,
            "updated_at": datetime.now(UTC).isoformat(),
        }
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
            failed_count = len(output.get("failed", []))
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
            "failed_count": len(self.checkpoint.failed),
            **event,
        }
        self.progress_callback(payload)


def _load_existing_output(path: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not path.exists():
        return {}, []

    data = json.loads(path.read_text(encoding="utf-8"))
    records: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for record in data.get("vulnerabilities", []):
        identity = _record_identity(record)
        if identity:
            records[identity] = record
            order.append(identity)
    return records, order


def _record_identity(record: dict[str, Any]) -> str | None:
    id_type = record.get("type")
    code = record.get("code")
    if id_type and code:
        return f"{str(id_type).lower()}:{code}"
    return None


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    tmp_path.replace(path)


def _format_nvd_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_nvd_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
