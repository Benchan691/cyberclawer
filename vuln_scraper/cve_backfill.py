from __future__ import annotations

from dataclasses import replace
from typing import Any

from .client import ScraperClient
from .config import ScraperSettings, mongo_collection_for_provider
from .models import normalize_cve_code
from .mongo import MongoSyncResult, sync_records_to_collection
from .scrapers.cve import CVEProvider


async def backfill_missing_cves(
    records: list[dict[str, Any]],
    settings: ScraperSettings,
    mongo_client: Any,
    *,
    scraped_at: str,
    client_factory: type[ScraperClient] = ScraperClient,
) -> MongoSyncResult:
    settings = settings.normalized()
    codes = _cve_codes_from_records(records, limit=settings.limit)
    if not codes:
        return MongoSyncResult()

    provider = CVEProvider()
    collection_name = mongo_collection_for_provider(
        provider.key,
        settings.mongo_config_file,
        default=provider.default_mongo_collection,
    )
    cve_collection = mongo_client[settings.mongo_database][collection_name]
    missing = _missing_codes(cve_collection, codes)
    if not missing:
        return MongoSyncResult()

    fetched_records: list[dict[str, Any]] = []
    async with client_factory(
        delay=max(settings.request_delay, provider.default_request_delay),
        retries=settings.retries,
        timeout=settings.timeout,
    ) as client:
        for code in missing[: settings.limit]:
            url = provider.cve_url(code)
            result = await client.get_json(url, headers=provider.request_headers())
            page = provider.parse_list(result.data, page=1)
            if not page.entries:
                continue
            fetched_records.append(page.entries[0].to_record(detail_url=url))

    if not fetched_records:
        return MongoSyncResult()

    cve_settings = replace(settings, mongo_collection=collection_name)
    return sync_records_to_collection(
        fetched_records,
        cve_settings,
        cve_collection,
        scraped_at=scraped_at,
        source={"provider": provider.key, "url": provider.source_url},
    )


def _cve_codes_from_records(records: list[dict[str, Any]], *, limit: int) -> list[str]:
    codes: list[str] = []
    for record in records:
        code = normalize_cve_code(str(record.get("cve_code"))) if record.get("cve_code") is not None else None
        if code and code not in codes:
            codes.append(code)
        if len(codes) >= limit:
            break
    return codes


def _missing_codes(collection: Any, codes: list[str]) -> list[str]:
    wanted_ids = {f"cve:{code}" for code in codes}
    existing_ids: set[str] = set()
    try:
        cursor = collection.find({"_id": {"$in": sorted(wanted_ids)}}, {"_id": 1})
        existing_ids = {str(document.get("_id")) for document in cursor if document.get("_id")}
    except Exception:
        existing_ids = {
            identity
            for identity in wanted_ids
            if collection.find_one({"_id": identity}) is not None
        }
    return [code for code in codes if f"cve:{code}" not in existing_ids]
