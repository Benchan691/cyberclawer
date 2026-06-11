from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from .config import ScraperSettings
from .error_log import log_uncaught_provider_error
from .providers import all_providers
from .runner import ScraperRunner

logger = logging.getLogger(__name__)

DEFAULT_MAX_RUNS_PER_PROVIDER = 100


def provider_caught_up(output: dict) -> bool:
    stop_reason = output.get("stop_reason")
    if stop_reason == "overlap":
        return True
    source = output.get("source") or {}
    if source.get("provider") == "cve" and output.get("result_count", 0) == 0:
        mongo = output.get("mongo_sync") or {}
        if mongo.get("inserted", 0) == 0:
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
) -> None:
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
        runs = 0
        scraped_total = 0
        last_stop_reason: str | None = None
        per_provider_limit = settings.limit

        while runs < max_runs_per_provider:
            remaining = per_provider_limit - scraped_total
            if remaining <= 0:
                logger.info(
                    "Provider %s reached per-provider limit=%s after %s run(s)",
                    provider.key,
                    per_provider_limit,
                    runs,
                )
                break

            runs += 1
            run_settings = replace(provider_settings, limit=remaining).normalized()
            logger.info(
                "Catch-up run %s for provider %s collection %s (remaining=%s/%s)",
                runs,
                provider.key,
                normalized.mongo_collection,
                remaining,
                per_provider_limit,
            )
            try:
                output = asyncio.run(
                    ScraperRunner(
                        run_settings,
                        provider=provider,
                        stop_on_first_known=True,
                    ).run()
                )
            except Exception as exc:
                logger.exception("Catch-up failed for provider %s run %s", provider.key, runs)
                log_uncaught_provider_error(
                    data_dir=normalized.data_dir,
                    error_log_name=normalized.error_log,
                    provider=provider.key,
                    error=exc,
                )
                break
            last_stop_reason = output.get("stop_reason")
            vulnerabilities = output.get("vulnerabilities", [])
            run_count = output.get("result_count", len(vulnerabilities))
            scraped_total += run_count
            completed = sum(
                1
                for item in vulnerabilities
                if isinstance(item.get("details"), dict)
                and isinstance(item["details"].get(provider.key), dict)
            )
            mongo = output.get("mongo_sync") or {}
            logger.info(
                "Provider %s run %s: fetched %s records (%s with details, stop_reason=%s, "
                "provider_total=%s/%s); inserted=%s overwritten=%s deleted=%s skipped=%s",
                provider.key,
                runs,
                len(vulnerabilities),
                completed,
                last_stop_reason,
                scraped_total,
                per_provider_limit,
                mongo.get("inserted", 0),
                mongo.get("overwritten", 0),
                mongo.get("deleted", 0),
                mongo.get("skipped", 0),
            )

            if scraped_total >= per_provider_limit:
                logger.info(
                    "Provider %s reached per-provider limit=%s after %s run(s)",
                    provider.key,
                    per_provider_limit,
                    runs,
                )
                break
            if provider_caught_up(output):
                logger.info("Provider %s caught up after %s run(s)", provider.key, runs)
                break
            if no_progress(output):
                logger.info(
                    "Provider %s stopped after %s run(s) with no forward progress",
                    provider.key,
                    runs,
                )
                break
        else:
            logger.warning(
                "Provider %s reached max_runs_per_provider=%s (last stop_reason=%s)",
                provider.key,
                max_runs_per_provider,
                last_stop_reason,
            )
