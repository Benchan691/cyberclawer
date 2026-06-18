from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import ScraperSettings
from .models import cve_codes as detail_cve_codes
from .models import normalize_cve_code
from .severity import severity_from_record


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
    return set(existing_documents_by_id(collection))


def existing_documents_by_id(collection: Any) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for document in collection.find({}):
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


_VOLATILE_PROVIDER_DETAIL_FIELDS: dict[str, frozenset[str]] = {
    # Qianxin read counters and article navigation metadata change between API calls.
    "qianxin": frozenset({"read_num", "prev_article", "next_article", "raw"}),
}


def sanitize_details_for_storage(details: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    sanitized = copy.deepcopy(details)
    hkcert = sanitized.get("hkcert")
    if isinstance(hkcert, dict):
        from vuln_scraper.scrapers.hkcert.parsers.detail import normalize_hkcert_detail

        sanitized["hkcert"] = normalize_hkcert_detail(hkcert)
    return sanitized


def sanitize_details_for_content_compare(details: dict[str, Any]) -> dict[str, Any]:
    sanitized = sanitize_details_for_storage(details)

    qianxin = sanitized.get("qianxin")
    if isinstance(qianxin, dict):
        from vuln_scraper.scrapers.qianxin.parsers.detail import normalize_qianxin_detail

        sanitized["qianxin"] = normalize_qianxin_detail(qianxin)

    for provider_key, provider_detail in sanitized.items():
        if not isinstance(provider_detail, dict):
            continue
        provider_detail.pop("raw_tables", None)
        for field in _VOLATILE_PROVIDER_DETAIL_FIELDS.get(provider_key, ()):
            provider_detail.pop(field, None)
    return sanitized


def document_content_payload(document: dict[str, Any]) -> dict[str, Any]:
    raw_cve = document.get("cve_code")
    if raw_cve is None:
        cve_code = None
    else:
        cve_code = normalize_cve_code(str(raw_cve))
        if cve_code is None:
            cve_code = raw_cve
    return {
        "title": document.get("title"),
        "cve_code": cve_code,
        "cve_codes": _normalized_document_cve_codes(document),
        "disclosure_date": document.get("disclosure_date"),
        "status": document.get("status"),
        "severity": document.get("severity") or "",
        "details": sanitize_details_for_content_compare(document.get("details") or {}),
    }


def _normalized_document_cve_codes(document: dict[str, Any]) -> list[str]:
    codes = _normalize_cve_codes(document.get("cve_codes"))
    cve_code = normalize_cve_code(str(document.get("cve_code"))) if document.get("cve_code") else None
    if cve_code and cve_code not in codes:
        codes.insert(0, cve_code)
    return codes


def _normalize_cve_codes(values: Any) -> list[str]:
    if values in (None, "", [], {}):
        return []
    candidates = values if isinstance(values, list) else [values]
    codes: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        if value in (None, ""):
            continue
        code = normalize_cve_code(str(value))
        if code is None:
            raise ValueError(f"invalid cve_codes item: {value!r}")
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _cve_codes_from_details(details: Any) -> list[str]:
    if not isinstance(details, dict):
        return []
    codes: list[str] = []
    seen: set[str] = set()
    for detail in details.values():
        if not isinstance(detail, dict):
            continue
        for code in detail_cve_codes(detail):
            if code not in seen:
                seen.add(code)
                codes.append(code)
    return codes


def _ensure_indexes(collection: Any) -> None:
    collection.create_index([("type", 1), ("code", 1)], unique=True)
    collection.create_index("cve_code")
    collection.create_index("cve_codes")
    collection.create_index("related_cves.cve_code")
    collection.create_index("disclosure_date")
    collection.create_index("status")
    collection.create_index("severity")


def _attach_related_cves(collection: Any, document: dict[str, Any]) -> None:
    document.pop("related_cves", None)
    document.pop("related_cve_ids", None)

    codes = document.get("cve_codes") or []
    if not codes:
        return

    database = getattr(collection, "database", None)
    if database is None:
        return

    links = _related_cve_links(database, codes)
    if not links:
        return
    document["related_cves"] = links
    document["related_cve_ids"] = [link["document_id"] for link in links]


def _related_cve_links(database: Any, codes: list[str]) -> list[dict[str, str]]:
    requested = list(dict.fromkeys(codes))
    query = _related_cve_query(requested)
    if not query:
        return []

    try:
        documents = database["cve"].find(
            query,
            {"_id": 1, "code": 1, "cve_code": 1, "cve_codes": 1, "details.cve.cve_id": 1},
        )
    except Exception:
        return []

    links_by_code: dict[str, dict[str, str]] = {}
    requested_set = set(requested)
    for cve_document in documents:
        document_id = str(cve_document.get("_id") or "")
        document_codes = _cve_codes_from_cve_document(cve_document)
        for code in document_codes:
            if code in requested_set and code not in links_by_code:
                links_by_code[code] = {
                    "collection": "cve",
                    "document_id": document_id or f"cve:{code}",
                    "cve_code": code,
                }

    return [links_by_code[code] for code in requested if code in links_by_code]


def _related_cve_query(codes: list[str]) -> dict[str, Any]:
    if not codes:
        return {}
    conditions = []
    for code in codes:
        prefixed = f"CVE-{code}"
        forms = [code, prefixed]
        conditions.extend(
            [
                {"_id": {"$in": [f"cve:{form}" for form in forms]}},
                {"code": {"$in": forms}},
                {"cve_code": {"$in": forms}},
                {"cve_codes": {"$in": forms}},
                {"details.cve.cve_id": {"$in": forms}},
            ]
        )
    return {"$or": conditions}


def _cve_codes_from_cve_document(document: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    document_id = document.get("_id")
    if isinstance(document_id, str):
        _, separator, suffix = document_id.partition(":")
        if separator:
            values.append(suffix)
    for field in ("code", "cve_code"):
        values.append(document.get(field))
    raw_codes = document.get("cve_codes")
    if isinstance(raw_codes, list):
        values.extend(raw_codes)
    detail = document.get("details")
    if isinstance(detail, dict):
        cve_detail = detail.get("cve")
        if isinstance(cve_detail, dict):
            values.append(cve_detail.get("cve_id"))

    codes: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in (None, ""):
            continue
        code = normalize_cve_code(str(value))
        if code and code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _sync_records(
    collection: Any,
    output: dict[str, Any],
    settings: ScraperSettings,
) -> MongoSyncResult:
    result = MongoSyncResult()
    for record in output.get("vulnerabilities", []):
        try:
            document = build_mongo_document(record, output)
            _attach_related_cves(collection, document)
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
    cve_codes = _normalize_cve_codes(document.get("cve_codes"))
    if not cve_codes:
        cve_codes = _cve_codes_from_details(document.get("details"))
    if cve_code and cve_code not in cve_codes:
        cve_codes.insert(0, cve_code)
    elif cve_code is None and cve_codes:
        cve_code = cve_codes[0]
    document["cve_code"] = cve_code
    document["cve_codes"] = cve_codes
    document.pop("cross_refs", None)
    document.setdefault("details", {})
    document["details"] = sanitize_details_for_storage(document["details"])
    document["severity"] = severity_from_record(document) or ""
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
    existing_core = copy.deepcopy({key: value for key, value in existing.items() if key not in ignored})
    document_core = copy.deepcopy({key: value for key, value in document.items() if key not in ignored})
    if "details" in existing_core:
        existing_core["details"] = sanitize_details_for_content_compare(existing_core["details"])
    if "details" in document_core:
        document_core["details"] = sanitize_details_for_content_compare(document_core["details"])
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
