from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from .config import MAX_RESULT_LIMIT, ScraperSettings, catch_up_provider_keys
from .email_alerts import load_email_alert_config, notify_scrape_exception
from .error_log import log_uncaught_provider_error
from .scrapers import ScraperProvider, all_providers, provider_keys
from .runner import ScraperRunner
from .source_catalog import sync_source_catalog_to_mongo
from .sync_state import SyncContext, catch_up_lock

logger = logging.getLogger(__name__)

CATCH_UP_BATCH_SIZE = 5
CATCH_UP_DEFAULT_LIMIT = MAX_RESULT_LIMIT
DEFAULT_MAX_RUNS_PER_PROVIDER = 100


def providers_for_catch_up(settings: ScraperSettings) -> list[ScraperProvider]:
    configured = catch_up_provider_keys(settings.scrapers_config_file)
    if configured is None:
        return all_providers()
    if not configured:
        return []

    known = set(provider_keys())
    by_key = {provider.key: provider for provider in all_providers()}
    selected: list[ScraperProvider] = []
    for key in configured:
        provider = by_key.get(key)
        if provider is None:
            # Configuration may lag a removed provider; skip instead of crashing.
            logger.warning(
                "Skipping unknown catch-up provider %r (not in the provider registry)",
                key,
            )
            continue
        selected.append(provider)
    return selected


def provider_caught_up(output: dict) -> bool:
    if output.get("failed") or (output.get("mongo_sync") or {}).get("errors"):
        return False
    if "sync" in output:
        return output["sync"].get("incremental_status") == "up_to_date"
    return output.get("stop_reason") in {"timestamp_boundary", "exhausted"}


def no_progress(output: dict) -> bool:
    if provider_caught_up(output):
        return False
    mongo = output.get("mongo_sync") or {}
    mongo_changed = (
        mongo.get("inserted", 0) > 0
        or mongo.get("overwritten", 0) > 0
        or mongo.get("deleted", 0) > 0
    )
    if output.get("result_count", 0) == 0:
        return not mongo_changed
    if (
        mongo.get("inserted", 0) == 0
        and mongo.get("overwritten", 0) == 0
        and mongo.get("deleted", 0) == 0
    ):
        return True
    return False


def run_catch_up_cycle(
    settings: ScraperSettings,
    *,
    max_runs_per_provider: int = DEFAULT_MAX_RUNS_PER_PROVIDER,
    batch_size: int = CATCH_UP_BATCH_SIZE,
    days: int = 1,
) -> None:
    context = SyncContext(overlap_days=days, batch_size=batch_size, max_pages=max_runs_per_provider)
    with catch_up_lock(settings.data_dir) as acquired:
        if not acquired:
            logger.info("Catch-up skipped: another invocation holds the progress lock")
            return
        _run_catch_up_cycle(settings, context)


def _run_catch_up_cycle(settings: ScraperSettings, context: SyncContext) -> None:
    selected_providers = providers_for_catch_up(settings)
    selected_keys = [provider.key for provider in selected_providers]
    if settings.mongo_enabled:
        catalog = sync_source_catalog_to_mongo(settings, providers=selected_keys)
        logger.info("Updated MongoDB source catalog with %s configured provider(s)", len(catalog["providers"]))
    logger.info("Catch-up provider selection from %s: %s", settings.scrapers_config_file,
                ", ".join(selected_keys) if selected_keys else "(none)")
    for provider in selected_providers:
        run_settings = replace(settings.for_provider(
            provider.key, default_collection=provider.default_mongo_collection,
            default_request_delay=provider.default_request_delay,
            default_concurrency=getattr(provider, "default_concurrency", None),
        ), mongo_conflict="overwrite").normalized()
        logger.info("Resumable catch-up for provider %s collection %s (overlap_days=%s, limit=%s)",
                    provider.key, run_settings.mongo_collection, context.overlap_days, run_settings.limit)
        try:
            output = asyncio.run(ScraperRunner(run_settings, provider=provider, sync_context=context).run())
        except Exception as exc:
            logger.exception("Catch-up failed for provider %s", provider.key)
            log_uncaught_provider_error(data_dir=run_settings.data_dir, error_log_name=run_settings.error_log,
                                        provider=provider.key, error=exc)
            try:
                notify_scrape_exception(load_email_alert_config(settings.scrapers_config_file),
                                        data_dir=run_settings.data_dir, provider=provider.key, error=exc)
            except Exception:
                logger.exception("scrape exception email alert failed for %s", provider.key)
            continue
        mongo = output.get("mongo_sync") or {}
        sync = output.get("sync") or {}
        logger.info(
            "Provider %s resumable catch-up: checked=%s fetched=%s stop_reason=%s "
            "incremental=%s history=%s pending_windows=%s pending_retries=%s "
            "inserted=%s overwritten=%s deleted=%s skipped=%s mongo_errors=%s",
            provider.key, sync.get("checked", output.get("result_count", 0)), output.get("result_count", 0),
            output.get("stop_reason"), sync.get("incremental_status", "unknown"),
            sync.get("history_status", "unknown"), sync.get("pending_windows", 0), sync.get("pending_retries", 0),
            mongo.get("inserted", 0), mongo.get("overwritten", 0), mongo.get("deleted", 0),
            mongo.get("skipped", 0), len(mongo.get("errors") or []),
        )
        for error in mongo.get("errors") or []:
            logger.error("MongoDB sync failed for %s advisory %s: %s", provider.key,
                         error.get("identity") or error.get("code") or "(unknown)", error.get("error"))
        if sync.get("history_gap"):
            logger.warning("%s source history cannot cover the saved position: %s", provider.key, sync["history_gap"])
