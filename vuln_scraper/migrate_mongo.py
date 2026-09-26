from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from .config import DEFAULT_MONGO_CONFIG_FILE, DEFAULT_MONGO_COLLECTION
from .schema_v2 import (
    PROHIBITED_FIELDS,
    SCHEMA_VERSION,
    convert_existing_document,
    ensure_v2_indexes,
    mongo_json_schema,
    validate_v2_document,
)


@dataclass(slots=True)
class MigrationResult:
    collection: str
    scanned: int = 0
    updated: int = 0
    shadow_collection: str = ""
    backup_collection: str = ""
    status: str = "planned"
    validation_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class UnifiedMigrationResult:
    """Result of merging provider collections into the single ``news`` collection."""

    collection: str = DEFAULT_MONGO_COLLECTION
    source_collections: list[str] = field(default_factory=list)
    scanned: int = 0
    inserted: int = 0
    duplicates: int = 0
    backup_collection: str = ""
    backup_collections: list[str] = field(default_factory=list)
    status: str = "planned"
    validation_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BACKUP_NAME_RE = re.compile(
    r"^(?P<provider>.+)__backup_(?P<stamp>\d{8}T\d{6}Z)$"
)


def cleanup_mongo_backups(
    database: Any,
    *,
    older_than_days: int = 7,
    dry_run: bool = True,
    now: datetime | None = None,
) -> list[str]:
    """List or explicitly remove timestamped migration backups past retention."""
    if older_than_days < 7:
        raise ValueError("v2 migration backups must be retained for at least seven days")
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=older_than_days)
    eligible: list[str] = []
    for name in database.list_collection_names():
        match = BACKUP_NAME_RE.fullmatch(name)
        if not match:
            continue
        created_at = datetime.strptime(
            match.group("stamp"), "%Y%m%dT%H%M%SZ"
        ).replace(tzinfo=timezone.utc)
        if created_at <= cutoff:
            eligible.append(name)
    eligible.sort()
    if not dry_run:
        for name in eligible:
            database[name].drop()
    return eligible


def migrate_mongo(
    database: Any,
    *,
    collections: list[str] | None = None,
    dry_run: bool = True,
    target_version: int = SCHEMA_VERSION,
    validate: bool = True,
    mongo_config_file: Any = DEFAULT_MONGO_CONFIG_FILE,
) -> list[MigrationResult]:
    if target_version != SCHEMA_VERSION:
        raise ValueError(f"unsupported MongoDB schema target: {target_version}")
    if collections is None:
        from .scrapers import all_providers

        names = sorted({provider.default_mongo_collection for provider in all_providers()})
    else:
        names = collections
    existing = set(database.list_collection_names())
    names = [name for name in names if name in existing and not name.endswith("_review")]
    results = [_plan_collection(database[name], name) for name in names]
    if dry_run:
        return results
    return _shadow_cutover(database, results, validate=validate)


def unify_mongo(
    database: Any,
    *,
    target_collection: str = DEFAULT_MONGO_COLLECTION,
    source_collections: list[str] | None = None,
    dry_run: bool = True,
    validate: bool = True,
) -> UnifiedMigrationResult:
    """Merge provider collections into one source-labelled collection.

    All conversion and validation happens in a shadow collection.  Cutover
    renames each physical source to a timestamped backup and explicitly rolls
    those renames back if any later rename fails.  Legacy review *views* are
    removed only after the shadow has passed validation; physical collections
    with a review-like name are never deleted.
    """
    from .scrapers import all_providers

    catalog = {
        str(item.get("name")): str(item.get("type") or "collection")
        for item in database.list_collections(filter={})
    }
    existing = set(catalog)
    legacy_names = {
        provider.default_mongo_collection for provider in all_providers()
    }
    if source_collections is None:
        candidates = [*legacy_names, target_collection]
        source_collections = sorted(
            {
                name
                for name in candidates
                if catalog.get(name) == "collection"
            }
        )
    else:
        requested = {str(name).strip() for name in source_collections if str(name).strip()}
        missing = sorted(name for name in requested if catalog.get(name) != "collection")
        if missing:
            return UnifiedMigrationResult(
                collection=target_collection,
                status="failed",
                validation_error=(
                    "Source collections do not exist as physical collections: "
                    + ", ".join(missing)
                ),
            )
        source_collections = sorted(
            {
                name
                for name in requested
                if not name.endswith("_review")
            }
        )

    result = UnifiedMigrationResult(
        collection=target_collection,
        source_collections=list(source_collections),
    )
    if not source_collections:
        result.status = "no_sources"
        return result

    providers = {provider.key for provider in all_providers()}
    records: dict[str, dict[str, Any]] = {}
    for collection_name in source_collections:
        for original in database[collection_name].find({}):
            result.scanned += 1
            provider = _infer_provider(original, collection_name, providers)
            if provider not in providers:
                result.status = "failed"
                result.validation_error = (
                    f"Cannot infer a supported provider for a document in {collection_name!r}."
                )
                return result
            try:
                converted = convert_existing_document(original, provider)
                converted["source"] = {
                    **(converted.get("source") if isinstance(converted.get("source"), dict) else {}),
                    "provider": provider,
                }
                if validate:
                    validate_v2_document(converted, "news")
            except Exception as exc:
                result.status = "failed"
                result.validation_error = f"{collection_name}: {exc}"
                return result
            identity = str(converted["_id"])
            previous = records.get(identity)
            if previous is not None:
                result.duplicates += 1
                previous_provider = (previous.get("source") or {}).get("provider")
                if previous_provider != provider:
                    result.status = "failed"
                    result.validation_error = f"Duplicate _id with different providers: {identity}"
                    return result
                old_time = previous.get("observed_at")
                new_time = converted.get("observed_at")
                if old_time == new_time and previous != converted:
                    result.status = "failed"
                    result.validation_error = (
                        f"Duplicate _id has conflicting content at the same observed_at: {identity}"
                    )
                    return result
                if new_time is not None and (old_time is None or new_time > old_time):
                    records[identity] = converted
                continue
            records[identity] = converted

    result.inserted = len(records)
    if source_collections == [target_collection]:
        result.status = "already_unified"
        return result
    result.status = "dry_run" if dry_run else "validated"
    if dry_run:
        return result

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    shadow_name = f"{target_collection}__unify_{timestamp}"
    legacy_sources = [name for name in source_collections if name != target_collection]
    target_backup = f"{target_collection}__backup_{timestamp}"
    source_backups = {
        name: f"{name}__backup_{timestamp}"
        for name in legacy_sources
    }
    reserved = {shadow_name, *source_backups.values()}
    if target_collection in existing:
        reserved.add(target_backup)
    collisions = sorted(reserved.intersection(existing))
    if collisions:
        result.status = "failed"
        result.validation_error = "Migration collection already exists: " + ", ".join(collisions)
        return result

    expected_review_names = {
        f"{name}_review" for name in {*legacy_names, *legacy_sources, target_collection}
    }
    physical_review_collections = sorted(
        name for name in expected_review_names if catalog.get(name) == "collection"
    )
    if physical_review_collections:
        result.status = "failed"
        result.validation_error = (
            "Refusing to delete physical review collections: "
            + ", ".join(physical_review_collections)
        )
        return result

    renamed_sources: list[tuple[str, str]] = []
    target_was_backed_up = False
    shadow_was_promoted = False
    try:
        database.create_collection(
            shadow_name,
            validator={"$jsonSchema": mongo_json_schema("news")},
            validationLevel="strict",
            validationAction="error",
        )
        shadow = database[shadow_name]
        batch: list[dict[str, Any]] = []
        for document in records.values():
            batch.append(document)
            if len(batch) >= 500:
                shadow.insert_many(batch, ordered=True)
                batch = []
        if batch:
            shadow.insert_many(batch, ordered=True)
        ensure_v2_indexes(shadow, "news")
        if shadow.count_documents({}) != len(records):
            raise RuntimeError("unified collection count does not match the validated input")
        shadow_ids = {document["_id"] for document in shadow.find({}, {"_id": 1})}
        if shadow_ids != set(records):
            raise RuntimeError("unified collection IDs do not match the validated input")

        for name in legacy_sources:
            backup = source_backups[name]
            database[name].rename(backup, dropTarget=False)
            renamed_sources.append((name, backup))
            result.backup_collections.append(backup)

        if target_collection in existing:
            database[target_collection].rename(target_backup, dropTarget=False)
            target_was_backed_up = True
            result.backup_collection = target_backup
            result.backup_collections.append(target_backup)
        database[shadow_name].rename(target_collection, dropTarget=False)
        shadow_was_promoted = True

        # View removal is deliberately last. The legacy application remains
        # usable if a physical rename fails, and a view-drop failure does not
        # undo an otherwise valid data cutover or discard the source backups.
        try:
            for name in sorted(expected_review_names):
                if catalog.get(name) == "view":
                    database[name].drop()
        except Exception as exc:
            result.status = "complete_with_warning"
            result.validation_error = f"Unified data is active, but a legacy view could not be removed: {exc}"
            return result
        result.status = "complete"
        return result
    except Exception as exc:
        names = set(database.list_collection_names())
        if shadow_was_promoted and target_collection in names:
            database[target_collection].rename(shadow_name, dropTarget=False)
            names.discard(target_collection)
            names.add(shadow_name)
        if target_was_backed_up and target_backup in names:
            database[target_backup].rename(target_collection, dropTarget=False)
            names.discard(target_backup)
            names.add(target_collection)
        for original, backup in reversed(renamed_sources):
            if backup in names and original not in names:
                database[backup].rename(original, dropTarget=False)
                names.discard(backup)
                names.add(original)
        if shadow_name in names:
            database[shadow_name].drop()
        result.status = "failed"
        result.validation_error = str(exc)
        result.backup_collection = ""
        result.backup_collections.clear()
        return result


def _infer_provider(
    document: dict[str, Any],
    collection_name: str,
    providers: set[str],
) -> str:
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    candidates = [
        source.get("provider"),
        document.get("type"),
        document.get("provider"),
    ]
    identity = document.get("_id")
    if isinstance(identity, str) and ":" in identity:
        candidates.append(identity.partition(":")[0])
    candidates.append(collection_name)
    for candidate in candidates:
        provider = str(candidate or "").strip().lower()
        if provider in providers:
            return provider
    return ""


def build_migration_update(document: dict[str, Any], collection_name: str) -> dict[str, Any]:
    """Return an update document for callers that migrate one document."""
    converted = convert_existing_document(document, collection_name)
    if converted == document:
        return {}
    set_values = {key: value for key, value in converted.items() if key != "_id"}
    unset = {key: "" for key in document if key not in converted and key != "_id"}
    update: dict[str, Any] = {"$set": set_values}
    if unset:
        update["$unset"] = unset
    return update


def _plan_collection(collection: Any, provider: str) -> MigrationResult:
    result = MigrationResult(
        collection=provider,
        shadow_collection=f"{provider}__v2",
    )
    for document in collection.find({}):
        result.scanned += 1
        converted = convert_existing_document(document, provider)
        if converted != document:
            result.updated += 1
    result.status = "already_v2" if result.updated == 0 else "planned"
    return result


def _shadow_cutover(
    database: Any,
    results: list[MigrationResult],
    *,
    validate: bool,
) -> list[MigrationResult]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prepared: list[MigrationResult] = []
    swapped: list[MigrationResult] = []
    try:
        for result in results:
            if result.status == "already_v2":
                continue
            provider = result.collection
            shadow_name = result.shadow_collection
            if shadow_name in database.list_collection_names():
                database[shadow_name].drop()
            database.create_collection(
                shadow_name,
                validator={"$jsonSchema": mongo_json_schema(provider)},
                validationLevel="strict",
                validationAction="error",
            )
            shadow = database[shadow_name]
            batch: list[dict[str, Any]] = []
            for document in database[provider].find({}):
                converted = convert_existing_document(document, provider)
                validate_v2_document(converted, provider)
                batch.append(converted)
                if len(batch) >= 500:
                    shadow.insert_many(batch, ordered=True)
                    batch = []
            if batch:
                shadow.insert_many(batch, ordered=True)
            ensure_v2_indexes(shadow, provider)
            if validate:
                _validate_shadow(database[provider], shadow, provider)
            result.status = "validated"
            prepared.append(result)

        if not prepared:
            return results

        _drop_review_views(database, [result.collection for result in prepared])
        for result in prepared:
            provider = result.collection
            backup = f"{provider}__backup_{timestamp}"
            database[provider].rename(backup, dropTarget=False)
            result.backup_collection = backup
            swapped.append(result)
            database[result.shadow_collection].rename(provider, dropTarget=False)
            result.status = "cutover"

        for result in prepared:
            result.status = "complete"
        return results
    except Exception as exc:
        _rollback_swaps(database, swapped)
        for result in prepared:
            if result.status not in {"already_v2", "complete"}:
                result.status = "rolled_back"
                result.validation_error = str(exc)
        raise RuntimeError(f"MongoDB v2 cutover failed and was rolled back: {exc}") from exc


def _validate_shadow(source: Any, shadow: Any, provider: str) -> None:
    source_ids = {document["_id"] for document in source.find({}, {"_id": 1})}
    shadow_ids = {document["_id"] for document in shadow.find({}, {"_id": 1})}
    if source_ids != shadow_ids:
        raise ValueError(f"{provider}: shadow _id set differs from source")
    for document in shadow.find({}):
        validate_v2_document(document, provider)
        prohibited = PROHIBITED_FIELDS.intersection(document)
        if prohibited:
            raise ValueError(f"{provider}: prohibited fields remain: {sorted(prohibited)}")
    if provider == "cve":
        source_count = source.count_documents({"classification": {"$exists": True}})
        shadow_count = shadow.count_documents({"classification": {"$exists": True}})
        if source_count != shadow_count:
            raise ValueError("cve: classification count changed during migration")


def _drop_review_views(database: Any, providers: list[str]) -> None:
    collection_types = {
        item["name"]: item.get("type")
        for item in database.list_collections(filter={})
    }
    for provider in providers:
        view_name = f"{provider}_review"
        if collection_types.get(view_name) == "view":
            database[view_name].drop()


def _rollback_swaps(database: Any, swapped: list[MigrationResult]) -> None:
    for result in reversed(swapped):
        provider = result.collection
        failed_name = f"{provider}__failed_v2"
        names = set(database.list_collection_names())
        if provider in names:
            if failed_name in names:
                database[failed_name].drop()
            database[provider].rename(failed_name, dropTarget=False)
        if result.backup_collection in database.list_collection_names():
            database[result.backup_collection].rename(provider, dropTarget=False)
