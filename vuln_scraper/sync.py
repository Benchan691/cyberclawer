from __future__ import annotations

import asyncio
import logging
import time

from .config import ScraperSettings
from .error_log import log_uncaught_provider_error
from .providers import all_providers
from .runner import ScraperRunner

logger = logging.getLogger(__name__)


def run_sync_cycle(settings: ScraperSettings, *, include_manual_verification: bool = False) -> None:
    for provider in all_providers():
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
        logger.info(
            "Starting MongoDB sync for provider %s collection %s",
            provider.key,
            normalized.mongo_collection,
        )
        try:
            output = asyncio.run(ScraperRunner(provider_settings, provider=provider).run())
        except Exception as exc:
            logger.exception("Sync failed for provider %s", provider.key)
            log_uncaught_provider_error(
                data_dir=normalized.data_dir,
                error_log_name=normalized.error_log,
                provider=provider.key,
                error=exc,
            )
            continue
        vulnerabilities = output.get("vulnerabilities", [])
        completed = sum(
            1
            for item in vulnerabilities
            if isinstance(item.get("details"), dict)
            and isinstance(item["details"].get(provider.key), dict)
        )
        logger.info(
            "Provider %s: fetched %s records (%s with details, limit=%s)",
            provider.key,
            len(vulnerabilities),
            completed,
            normalized.limit,
        )
        mongo = output.get("mongo_sync")
        if mongo:
            logger.info(
                "Provider %s MongoDB sync: inserted=%s overwritten=%s skipped=%s conflicts=%s",
                provider.key,
                mongo["inserted"],
                mongo["overwritten"],
                mongo["skipped"],
                mongo["conflicts"],
            )


def run_periodic_sync(
    hours: float,
    settings: ScraperSettings,
    *,
    include_manual_verification: bool = False,
) -> None:
    interval_seconds = hours * 3600
    logger.info("Periodic sync every %s hour(s)", hours)
    try:
        while True:
            logger.info("Sync cycle starting")
            run_sync_cycle(settings, include_manual_verification=include_manual_verification)
            logger.info("Sync cycle complete; sleeping for %s hour(s)", hours)
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logger.info("Periodic sync stopped")
