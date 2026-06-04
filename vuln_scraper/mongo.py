from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import ScraperSettings
from .models import normalize_cve_code


MongoClientFactory = Callable[[str], Any]


@dataclass(slots=True)
class MongoSyncResult:
    inserted: int = 0
    overwritten: int = 0
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
        _ensure_indexes(collection)
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
    _ensure_indexes(collection)
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


def existing_identity_keys(collection: Any) -> set[str]:
    ids: set[str] = set()
    for document in collection.find({}, {"_id": 1, "type": 1, "code": 1}):
        identity = document.get("_id")
        if not identity and document.get("type") and document.get("code"):
            identity = f"{str(document['type']).lower()}:{document['code']}"
        if identity:
            ids.add(_canonical_identity_key(str(identity)))
    return ids


def _ensure_indexes(collection: Any) -> None:
    collection.create_index([("type", 1), ("code", 1)], unique=True)
    collection.create_index("cve_code")
    collection.create_index("disclosure_date")
    collection.create_index("status")


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
    id_type = str(record.get("type") or "").strip().lower()
    code = str(record.get("code") or "").strip()
    if not id_type or not code:
        raise ValueError("type and code are required for MongoDB sync")

    document = copy.deepcopy(record)
    document["type"] = id_type
    document["code"] = code
    document["_id"] = f"{id_type}:{code}"
    raw_cve_code = document.get("cve_code")
    cve_code = normalize_cve_code(str(raw_cve_code)) if raw_cve_code is not None else None
    if raw_cve_code is not None and cve_code is None:
        raise ValueError(f"invalid cve_code: {raw_cve_code!r}")
    document["cve_code"] = cve_code
    document.pop("cross_refs", None)
    document.setdefault("details", {})
    document["scraped_at"] = output.get("scraped_at")
    if isinstance(record.get("source"), dict):
        document["source"] = record["source"]
    else:
        document["source"] = output.get("source")
    return document


def _sync_one(
    collection: Any,
    document: dict[str, Any],
    settings: ScraperSettings,
    result: MongoSyncResult,
) -> None:
    identity = document["_id"]
    existing = collection.find_one({"_id": identity})
    if existing is None:
        collection.insert_one(document)
        result.inserted += 1
        return

    if _documents_match(existing, document):
        result.skipped += 1
        result.unchanged += 1
        return

    result.conflicts += 1
    if _should_overwrite(document, existing, settings):
        collection.replace_one({"_id": identity}, document, upsert=True)
        result.overwritten += 1
    else:
        result.skipped += 1


def _documents_match(existing: dict[str, Any], document: dict[str, Any]) -> bool:
    ignored = {"scraped_at", "source"}
    existing_core = {key: value for key, value in existing.items() if key not in ignored}
    document_core = {key: value for key, value in document.items() if key not in ignored}
    return existing_core == document_core


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
