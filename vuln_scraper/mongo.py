from __future__ import annotations

import copy
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import ScraperSettings
from .schema_v2 import build_v2_document, ensure_v2_indexes


MongoClientFactory = Callable[[str], Any]


@dataclass(slots=True)
class MongoSyncResult:
    inserted: int = 0
    overwritten: int = 0
    deleted: int = 0
    skipped: int = 0
    conflicts: int = 0
    unchanged: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sync_output_to_mongo(
    output: dict[str, Any],
    settings: ScraperSettings,
    *,
    client_factory: MongoClientFactory | None = None,
) -> MongoSyncResult:
    normalized = settings.normalized()
    if not normalized.mongo_enabled:
        return MongoSyncResult()

    factory = client_factory or _default_client_factory
    client = factory(normalized.mongo_uri or "")
    try:
        collection = client[normalized.mongo_database][normalized.mongo_collection]
        _ensure_indexes(collection, normalized.mongo_collection)
        return _sync_records(collection, output, normalized)
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


def sync_records_to_collection(
    records: list[dict[str, Any]],
    settings: ScraperSettings,
    collection: Any,
    *,
    scraped_at: str,
    source: Any,
) -> MongoSyncResult:
    _ensure_indexes(collection, settings.normalized().mongo_collection)
    output = {
        "scraped_at": scraped_at,
        "source": source,
        "vulnerabilities": records,
    }
    return _sync_records(collection, output, settings.normalized())


def redact_mongo_uri(uri: str | None) -> str | None:
    if not uri:
        return uri
    parsed = urlsplit(uri)
    if "@" not in parsed.netloc:
        return uri
    credentials, host = parsed.netloc.rsplit("@", 1)
    username = credentials.split(":", 1)[0]
    redacted_netloc = f"{username}:***@{host}" if username else f"***@{host}"
    return urlunsplit((parsed.scheme, redacted_netloc, parsed.path, parsed.query, parsed.fragment))


def _default_client_factory(uri: str) -> Any:
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise RuntimeError("pymongo is required for --mongo-sync. Install this package again.") from exc

    return MongoClient(uri, serverSelectionTimeoutMS=5000)


def create_mongo_client(uri: str) -> Any:
    return _default_client_factory(uri)


def collection_from_settings(
    settings: ScraperSettings,
    *,
    client_factory: MongoClientFactory | None = None,
) -> tuple[Any, Any]:
    normalized = settings.normalized()
    factory = client_factory or create_mongo_client
    client = factory(normalized.mongo_uri or "")
    collection = client[normalized.mongo_database][normalized.mongo_collection]
    return client, collection


def existing_identity_keys(collection: Any, *, provider: str | None = None) -> set[str]:
    return set(existing_documents_by_id(collection, provider=provider))


def existing_documents_by_id(
    collection: Any,
    *,
    provider: str | None = None,
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    query = (
        {
            "$or": [
                {"source.provider": provider},
                {"_id": {"$regex": rf"^{re.escape(provider)}:"}},
            ]
        }
        if provider
        else {}
    )
    for document in collection.find(query):
        identity = document.get("_id")
        if not identity and document.get("type") and document.get("code"):
            identity = f"{str(document['type']).lower()}:{document['code']}"
        if identity:
            documents[_canonical_identity_key(str(identity))] = document
    return documents


def documents_match(existing: dict[str, Any], document: dict[str, Any]) -> bool:
    return _documents_match(existing, document)


def documents_content_match(existing: dict[str, Any], document: dict[str, Any]) -> bool:
    return document_content_payload(existing) == document_content_payload(document)


def sanitize_details_for_storage(details: dict[str, Any]) -> dict[str, Any]:
    """Compatibility helper for callers comparing already-built v2 documents."""
    return copy.deepcopy(details) if isinstance(details, dict) else {}


def sanitize_details_for_content_compare(details: dict[str, Any]) -> dict[str, Any]:
    return sanitize_details_for_storage(details)


def document_content_payload(document: dict[str, Any]) -> dict[str, Any]:
    payload = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key not in {"_id", "observed_at", "source", "classification"}
    }
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    payload["source_provider"] = source.get("provider")
    return _mongo_comparison_value(payload)


def _mongo_comparison_value(value: Any) -> Any:
    """Compare timestamps as BSON stores them: UTC with millisecond precision."""
    if isinstance(value, datetime):
        normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return normalized.replace(microsecond=(normalized.microsecond // 1000) * 1000)
    if isinstance(value, dict):
        return {key: _mongo_comparison_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mongo_comparison_value(item) for item in value]
    return value


def _ensure_indexes(collection: Any, provider: str | None = None) -> None:
    # The configured collection name is operator-defined and no longer carries
    # provider meaning.  Every runtime collection uses the unified indexes.
    ensure_v2_indexes(collection, "news")


def _sync_records(
    collection: Any,
    output: dict[str, Any],
    settings: ScraperSettings,
) -> MongoSyncResult:
    result = MongoSyncResult()
    for record in output.get("vulnerabilities", []):
        try:
            document = build_mongo_document(record, output)
            _sync_one(collection, document, settings, result)
        except Exception as exc:
            result.errors.append(
                {
                    "identity": _identity_key(record),
                    "type": record.get("type"),
                    "code": record.get("code"),
                    "error": str(exc),
                }
            )
    return result


def build_mongo_document(record: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    return build_v2_document(record, output)


def _sync_one(
    collection: Any,
    document: dict[str, Any],
    settings: ScraperSettings,
    result: MongoSyncResult,
) -> None:
    identity = document["_id"]
    existing = collection.find_one({"_id": identity})
    if existing is None:
        written = collection.insert_one(document)
        if getattr(written, "acknowledged", True) is False:
            raise RuntimeError("MongoDB insert was not acknowledged")
        result.inserted += 1
        return

    if _documents_match(existing, document):
        result.skipped += 1
        result.unchanged += 1
        return

    result.conflicts += 1
    existing_source = existing.get("source") if isinstance(existing.get("source"), dict) else {}
    document_source = document.get("source") if isinstance(document.get("source"), dict) else {}
    repairs_provider = existing_source.get("provider") != document_source.get("provider")
    if repairs_provider or _should_overwrite(document, existing, settings):
        if document["_id"].startswith("cve:") and isinstance(existing.get("classification"), dict):
            document["classification"] = existing["classification"]
        written = collection.replace_one({"_id": identity}, document, upsert=True)
        if getattr(written, "acknowledged", True) is False:
            raise RuntimeError("MongoDB replacement was not acknowledged")
        result.overwritten += 1
    else:
        result.skipped += 1


def _documents_match(existing: dict[str, Any], document: dict[str, Any]) -> bool:
    ignored = {"scraped_at", "observed_at", "source", "classification"}
    existing_core = copy.deepcopy({key: value for key, value in existing.items() if key not in ignored})
    document_core = copy.deepcopy({key: value for key, value in document.items() if key not in ignored})
    if "details" in existing_core:
        existing_core["details"] = sanitize_details_for_content_compare(existing_core["details"])
    if "details" in document_core:
        document_core["details"] = sanitize_details_for_content_compare(document_core["details"])
    existing_source = existing.get("source") if isinstance(existing.get("source"), dict) else {}
    document_source = document.get("source") if isinstance(document.get("source"), dict) else {}
    return (
        _mongo_comparison_value(existing_core) == _mongo_comparison_value(document_core)
        and existing_source.get("provider") == document_source.get("provider")
    )


def _should_overwrite(
    document: dict[str, Any],
    existing: dict[str, Any],
    settings: ScraperSettings,
) -> bool:
    if settings.mongo_conflict == "overwrite":
        return True
    if settings.mongo_conflict != "prompt" or not settings.mongo_interactive:
        return False

    identity = document["_id"]
    title = document.get("title") or existing.get("title") or ""
    prompt = f"MongoDB conflict for {identity} {title!r}. Overwrite? [y/N]: "
    answer = input(prompt).strip().lower()
    return answer in {"y", "yes"}


def _identity_key(record: dict[str, Any]) -> str | None:
    if record.get("type") and record.get("code"):
        return f"{str(record['type']).lower()}:{record['code']}"
    return None


def _canonical_identity_key(identity: str) -> str:
    id_type, separator, code = identity.partition(":")
    if not separator:
        return identity
    return f"{id_type.lower()}:{code}"
