from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from .config import MAX_RESULT_LIMIT, ScraperSettings, catch_up_provider_keys
from .error_log import log_uncaught_provider_error
from .scrapers import ScraperProvider, all_providers, provider_keys
from .runner import ScraperRunner
from .source_catalog import sync_source_catalog_to_mongo
from .timestamps import window_start

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
    stop_reason = output.get("stop_reason")
    if stop_reason == "timestamp_boundary":
        return True
    return False


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
    selected_providers = providers_for_catch_up(settings)
    selected_keys = [provider.key for provider in selected_providers]
    if settings.mongo_enabled:
        catalog = sync_source_catalog_to_mongo(settings, providers=selected_keys)
        logger.info(
            "Updated MongoDB source catalog with %s configured provider(s)",
            len(catalog["providers"]),
        )
    logger.info(
        "Catch-up provider selection from %s: %s",
        settings.scrapers_config_file,
        ", ".join(selected_keys) if selected_keys else "(none)",
    )
    for provider in selected_providers:
        provider_settings = settings.for_provider(
            provider.key,
            default_collection=provider.default_mongo_collection,
            default_request_delay=provider.default_request_delay,
            default_concurrency=getattr(provider, "default_concurrency", None),
        )
        normalized = provider_settings.normalized()
        runs = 0
        scraped_total = 0
        last_stop_reason: str | None = None
        per_provider_limit = settings.limit
        updated_since = window_start(days)

        runs += 1
        run_settings = replace(
            provider_settings,
            limit=per_provider_limit,
            mongo_conflict="overwrite",
        ).normalized()
        logger.info(
            "Timestamp catch-up for provider %s collection %s "
            "(updated_since=%s, days=%s, limit=%s)",
            provider.key,
            normalized.mongo_collection,
            updated_since.isoformat(),
            days,
            per_provider_limit,
        )
        try:
            output = asyncio.run(
                ScraperRunner(
                    run_settings,
                    provider=provider,
                    updated_since=updated_since,
                ).run()
            )
        except Exception as exc:
            logger.exception("Timestamp catch-up failed for provider %s", provider.key)
            log_uncaught_provider_error(
                data_dir=normalized.data_dir,
                error_log_name=normalized.error_log,
                provider=provider.key,
                error=exc,
            )
            continue

        last_stop_reason = output.get("stop_reason")
        vulnerabilities = output.get("vulnerabilities", [])
        scraped_total = output.get("result_count", len(vulnerabilities))
        completed = sum(
            1
            for item in vulnerabilities
            if isinstance(item.get("details"), dict)
            and isinstance(item["details"].get(provider.key), dict)
        )
        mongo = output.get("mongo_sync") or {}
        logger.info(
            "Provider %s timestamp catch-up: fetched %s window records "
            "(%s with details, stop_reason=%s); inserted=%s overwritten=%s deleted=%s skipped=%s",
            provider.key,
            len(vulnerabilities),
            completed,
            last_stop_reason,
            mongo.get("inserted", 0),
            mongo.get("overwritten", 0),
            mongo.get("deleted", 0),
            mongo.get("skipped", 0),
        )
