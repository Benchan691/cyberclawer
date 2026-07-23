from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vuln_scraper.config import DEFAULT_MONGO_CONFIG_FILE, mongo_collection_for_provider
from vuln_scraper.mongo import _ensure_indexes
from vuln_scraper.scrapers import get_provider, provider_keys
from vuln_scraper.severity import severity_from_record


@dataclass(slots=True)
class BackfillSeverityResult:
    provider: str
    collection_name: str
    scanned: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: bool = False
    message: str = ""


def backfill_collection_severity(
    collection: Any,
    *,
    provider: str | None = None,
    batch_size: int = 500,
    dry_run: bool = False,
) -> tuple[int, int, int]:
    if not dry_run:
        _ensure_indexes(collection, provider)

    scanned = 0
    updated = 0
    unchanged = 0
    pending: list[Any] = []

    for document in collection.find({}, {"type": 1, "status": 1, "details": 1, "severity": 1}):
        scanned += 1
        new_severity = severity_from_record(document) or ""
        old_severity = document.get("severity")
        if old_severity == new_severity:
            unchanged += 1
            continue

        updated += 1
        if dry_run:
            continue

        pending.append(_build_update(document["_id"], new_severity))
        if len(pending) >= batch_size:
            _flush_updates(collection, pending)
            pending.clear()

    if pending:
        _flush_updates(collection, pending)

    return scanned, updated, unchanged


def backfill_severity(
    database: Any,
    *,
    providers: list[str] | None = None,
    mongo_config_file: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[BackfillSeverityResult]:
    keys = list(providers) if providers else list(provider_keys())
    results: list[BackfillSeverityResult] = []
    existing = {item["name"] for item in database.list_collections(filter={})}

    for key in keys:
        provider = get_provider(key)
        collection_name = mongo_collection_for_provider(
            key,
            mongo_config_file,
            default=provider.default_mongo_collection,
        )
        if collection_name not in existing:
            results.append(
                BackfillSeverityResult(
                    provider=key,
                    collection_name=collection_name,
                    skipped=True,
                    message="collection missing",
                )
            )
            continue

        scanned, updated, unchanged = backfill_collection_severity(
            database[collection_name],
            provider=key,
            batch_size=batch_size,
            dry_run=dry_run,
        )
        results.append(
            BackfillSeverityResult(
                provider=key,
                collection_name=collection_name,
                scanned=scanned,
                updated=updated,
                unchanged=unchanged,
            )
        )
    return results


def _build_update(document_id: Any, severity: str) -> Any:
    try:
        from pymongo import UpdateOne
    except ImportError as exc:
        raise RuntimeError("pymongo is required for severity backfill. Install this package again.") from exc

    return UpdateOne({"_id": document_id}, {"$set": {"severity": severity}})


def _flush_updates(collection: Any, updates: list[Any]) -> None:
    if not updates:
        return
    collection.bulk_write(updates, ordered=False)
