from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from .config import ScraperSettings, catch_up_provider_keys
from .scrapers import provider_keys

SOURCE_CATALOG_COLLECTION = "source_catalog"
SOURCE_CATALOG_ID = "active"
MongoClientFactory = Callable[[str], Any]


def configured_source_keys(scrapers_config_file: Any = None) -> list[str]:
    configured = catch_up_provider_keys(scrapers_config_file)
    if configured is None:
        return list(provider_keys())

    available = set(provider_keys())
    return [key for key in configured if key in available]


def source_catalog_document(
    providers: Sequence[str], *, updated_at: datetime | None = None
) -> dict[str, Any]:
    available = set(provider_keys())
    normalized: list[str] = []
    seen: set[str] = set()
    for provider in providers:
        key = str(provider).strip()
        if not key or key in seen:
            continue
        if key not in available:
            raise ValueError(f"unknown source catalog provider: {key}")
        seen.add(key)
        normalized.append(key)
    return {
        "_id": SOURCE_CATALOG_ID,
        "providers": normalized,
        "updated_at": updated_at or datetime.now(UTC),
    }


def write_source_catalog(
    database: Any,
    providers: Sequence[str],
    *,
    updated_at: datetime | None = None,
) -> dict[str, Any]:
    document = source_catalog_document(providers, updated_at=updated_at)
    database[SOURCE_CATALOG_COLLECTION].replace_one(
        {"_id": SOURCE_CATALOG_ID}, document, upsert=True
    )
    return document


def sync_source_catalog_to_mongo(
    settings: ScraperSettings,
    *,
    providers: Sequence[str] | None = None,
    client_factory: MongoClientFactory | None = None,
) -> dict[str, Any]:
    normalized = settings.normalized()
    if not normalized.mongo_enabled:
        raise ValueError("MongoDB must be enabled to sync the source catalog.")

    keys = list(providers) if providers is not None else configured_source_keys(
        normalized.scrapers_config_file
    )
    if client_factory is None:
        from .mongo import create_mongo_client

        client_factory = create_mongo_client

    client = client_factory(normalized.mongo_uri or "")
    try:
        database = client[normalized.mongo_database]
        return write_source_catalog(database, keys)
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()
