from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from .config import MAX_RESULT_LIMIT, ScraperSettings, catch_up_provider_keys
from .error_log import log_uncaught_provider_error
from .providers import ScraperProvider, all_providers, provider_keys
from .runner import ScraperRunner
from .timestamps import today_start

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
    unknown = [key for key in configured if key not in known]
    if unknown:
        choices = ", ".join(provider_keys())
        bad = ", ".join(unknown)
        raise ValueError(f"unknown catch-up provider(s): {bad}; choose from: {choices}")

    by_key = {provider.key: provider for provider in all_providers()}
    return [by_key[key] for key in configured]


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
    include_manual_verification: bool = False,
    max_runs_per_provider: int = DEFAULT_MAX_RUNS_PER_PROVIDER,
    batch_size: int = CATCH_UP_BATCH_SIZE,
) -> None:
    selected_providers = providers_for_catch_up(settings)
    selected_keys = [provider.key for provider in selected_providers]
    logger.info(
        "Catch-up provider selection from %s: %s",
        settings.scrapers_config_file,
        ", ".join(selected_keys) if selected_keys else "(none)",
    )
    for provider in selected_providers:
        if getattr(provider, "manual_verification", False) and not include_manual_verification:
            logger.info(
                "Skipping provider %s because it requires manual browser verification",
                provider.key,
            )
            continue

        provider_settings = settings.for_provider(
            provider.key,
            default_collection=provider.default_mongo_collection,
            browser_fallback=provider.browser_fallback,
            default_request_delay=provider.default_request_delay,
            default_concurrency=getattr(provider, "default_concurrency", None),
            manual_verification=getattr(provider, "manual_verification", None),
        )
        normalized = provider_settings.normalized()
        runs = 0
        scraped_total = 0
        last_stop_reason: str | None = None
        per_provider_limit = settings.limit
        updated_since = today_start()

        if provider.key == "cve":
            run_settings = replace(
                provider_settings,
                mongo_conflict="overwrite",
            ).normalized()
            logger.info(
                "CVE timestamp catch-up for collection %s (fetches CVEProject data from raw.githubusercontent.com, not github_advisory)",
                normalized.mongo_collection,
            )
            try:
                output = asyncio.run(
                    ScraperRunner(
                        run_settings,
                        provider=provider,
                        cve_delta_catch_up=True,
                    ).run()
                )
            except Exception as exc:
                logger.exception("CVE timestamp catch-up failed")
                log_uncaught_provider_error(
                    data_dir=normalized.data_dir,
                    error_log_name=normalized.error_log,
                    provider=provider.key,
                    error=exc,
                )
                continue
            mongo = output.get("mongo_sync") or {}
            logger.info(
                "CVE timestamp catch-up: fetched=%s stop_reason=%s; "
                "inserted=%s overwritten=%s skipped=%s errors=%s",
                output.get("result_count", 0),
                output.get("stop_reason"),
                mongo.get("inserted", 0),
                mongo.get("overwritten", 0),
                mongo.get("skipped", 0),
                len(mongo.get("errors", [])),
            )
            continue

        runs += 1
        run_settings = replace(
            provider_settings,
            limit=per_provider_limit,
            mongo_conflict="overwrite",
        ).normalized()
        logger.info(
            "Timestamp catch-up for provider %s collection %s (updated_since=%s, limit=%s)",
            provider.key,
            normalized.mongo_collection,
            updated_since.isoformat(),
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
            "Provider %s timestamp catch-up: fetched %s today-window records "
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
