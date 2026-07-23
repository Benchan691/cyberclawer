from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from .config import DEFAULT_MONGO_CONFIG_FILE, mongo_collections_from_config
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


BACKUP_NAME_RE = re.compile(
    r"^(?P<provider>[a-z0-9_]+)__backup_(?P<stamp>\d{8}T\d{6}Z)$"
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
    names = collections or sorted(set(mongo_collections_from_config(mongo_config_file).values()))
    existing = set(database.list_collection_names())
    names = [name for name in names if name in existing and not name.endswith("_review")]
    results = [_plan_collection(database[name], name) for name in names]
    if dry_run:
        return results
    return _shadow_cutover(database, results, validate=validate)


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
                _validate_shadow_review(database, shadow_name, provider)
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

        from .review_template import refresh_review_views

        refreshed = refresh_review_views(
            database,
            providers=[result.collection for result in prepared],
        )
        failures = [item for item in refreshed if not item.refreshed]
        if failures:
            raise RuntimeError(
                "review view validation failed: "
                + "; ".join(f"{item.provider}: {item.message}" for item in failures)
            )
        for result in prepared:
            result.status = "complete"
        return results
    except Exception as exc:
        _rollback_swaps(database, swapped)
        _restore_review_views(database, [result.collection for result in swapped])
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
    from .review_template import review_template_from_document

    source_reviews = {
        document["_id"]: review_template_from_document(document)
        for document in source.find({})
    }
    for document in shadow.find({}):
        validate_v2_document(document, provider)
        prohibited = PROHIBITED_FIELDS.intersection(document)
        if prohibited:
            raise ValueError(f"{provider}: prohibited fields remain: {sorted(prohibited)}")
        before = source_reviews[document["_id"]]
        after = review_template_from_document(document)
        lost_text = any(
            before[field] not in ("", "Unknown") and before[field] != after[field]
            for field in ("title", "description", "impacts", "recommendation")
        )
        lost_arrays = any(
            before[field] and before[field] != after[field]
            for field in ("affected", "related_link")
        )
        if lost_text or lost_arrays:
            raise ValueError(
                f"{provider}: review output changed for {document['_id']}"
            )
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


def _validate_shadow_review(database: Any, shadow_name: str, provider: str) -> None:
    from .review_template import _validate_review_view, review_view_pipeline

    view_name = f"{shadow_name}_review"
    if view_name in database.list_collection_names():
        database[view_name].drop()
    database.command(
        {
            "create": view_name,
            "viewOn": shadow_name,
            "pipeline": review_view_pipeline(provider),
        }
    )
    try:
        _validate_review_view(database, view_name)
    finally:
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


def _restore_review_views(database: Any, providers: list[str]) -> None:
    if not providers:
        return
    from .review_template import refresh_review_views

    refresh_review_views(database, providers=providers)
