from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import normalize_cve_code
from .severity import CANONICAL_SEVERITIES, normalize_severity, severity_from_record
from .timestamps import document_published_time, document_updated_time, parse_timestamp


SCHEMA_VERSION = 2
PROHIBITED_FIELDS = frozenset(
    {
        "type",
        "cve_code",
        "cve_codes",
        "related_cves",
        "related_cve_ids",
        "vuln_type",
        "disclosure_date",
        "published_time",
        "updated_time",
        "scraped_at",
        "status",
    }
)
CLASSIFICATION_DATE_FIELDS = frozenset(
    {"updated_at", "classified_at", "queued_at", "processing_started_at"}
)


@dataclass(frozen=True, slots=True)
class ProviderSchema:
    identity_fields: tuple[str, ...] = ()
    title_fields: tuple[str, ...] = ()
    cve_fields: tuple[str, ...] = ()
    severity_fields: tuple[str, ...] = ()
    published_fields: tuple[str, ...] = ()
    updated_fields: tuple[str, ...] = ()
    source_fields: tuple[str, ...] = ()
    volatile_fields: tuple[str, ...] = ()


PROVIDER_SCHEMAS: dict[str, ProviderSchema] = {
    "avd": ProviderSchema(
        cve_fields=("cve_id",),
        severity_fields=("danger_level",),
        published_fields=("attack_metrics.disclosure_date",),
    ),
    "cisco": ProviderSchema(
        identity_fields=("advisory_id",),
        title_fields=("title",),
        cve_fields=("cve_id", "cve_ids"),
        severity_fields=("sir",),
        published_fields=("first_published",),
        updated_fields=("last_updated",),
        source_fields=("publication_url",),
    ),
    "cnnvd": ProviderSchema(
        identity_fields=("cnnvdId",),
        title_fields=("vulName",),
        cve_fields=("cveId", "cveCode"),
        severity_fields=("vulLevel", "hazardLevel"),
        published_fields=("publishDate", "publishTime"),
        updated_fields=("updateTime",),
    ),
    "cnvd": ProviderSchema(
        identity_fields=("cnvd_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("published_date",),
        updated_fields=("updated_date",),
        volatile_fields=(
            "click_count", "comment_count", "follow_count",
            "clickCount", "commentCount", "followCount",
        ),
    ),
    "cve": ProviderSchema(
        identity_fields=("cve_id",),
        title_fields=("title",),
        cve_fields=("cve_id",),
        published_fields=("published",),
        updated_fields=("last_modified",),
        volatile_fields=("vuln_status", "affected_products"),
    ),
    "fortiguard": ProviderSchema(
        identity_fields=("advisory_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("published_date",),
        source_fields=("csaf_url", "cvrf_url"),
    ),
    "github_advisory": ProviderSchema(
        identity_fields=("ghsa_id",),
        cve_fields=("cve_id", "cve_ids"),
        severity_fields=("severity",),
        published_fields=("published_at",),
        updated_fields=("updated_at",),
        source_fields=("html_url", "api_url"),
    ),
    "govcert": ProviderSchema(
        identity_fields=("alert_code",),
        cve_fields=("cve_ids",),
        published_fields=("published_date",),
    ),
    "hikvision": ProviderSchema(
        identity_fields=("advisory_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("initial_release_date", "published_date"),
        updated_fields=("updated_date",),
    ),
    "hkcert": ProviderSchema(
        cve_fields=("vulnerability_identifiers",),
        severity_fields=("risk_level",),
        published_fields=("release_date",),
        updated_fields=("last_update_date",),
        volatile_fields=("views",),
    ),
    "hpe": ProviderSchema(
        identity_fields=("doc_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("release_date", "published_date"),
        updated_fields=("last_updated",),
    ),
    "huawei_sa": ProviderSchema(
        identity_fields=("sasnNo", "sasnId"),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("publishDate",),
    ),
    "infosec": ProviderSchema(
        identity_fields=("alert_code",),
        cve_fields=("cve_ids",),
        published_fields=("published_date",),
    ),
    "juniper": ProviderSchema(
        identity_fields=("article_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        published_fields=("published_date",),
        updated_fields=("updated_date",),
    ),
    "msrc": ProviderSchema(
        identity_fields=("cve_id", "document_id"),
        title_fields=("title",),
        cve_fields=("cve_id",),
        published_fields=("initial_release_date",),
        updated_fields=("current_release_date",),
    ),
    "paloalto": ProviderSchema(
        identity_fields=("advisory_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("severity",),
        published_fields=("published_date",),
        updated_fields=("updated_date",),
    ),
    "qianxin": ProviderSchema(
        identity_fields=("article_id",),
        title_fields=("title",),
        cve_fields=("cve_ids",),
        severity_fields=("level",),
        published_fields=("published_at", "published_date"),
        updated_fields=("updated_at", "updated_date"),
        volatile_fields=("read_num", "prev_article", "next_article"),
    ),
    "ransomwarelive": ProviderSchema(
        title_fields=("victim",),
        published_fields=("attackdate",),
        updated_fields=("discovered",),
    ),
    "splunk": ProviderSchema(
        identity_fields=("advisory_id",),
        title_fields=("title",),
        cve_fields=("cve_id", "cve_ids"),
        severity_fields=("severity",),
        published_fields=("published_date",),
        updated_fields=("last_modified",),
    ),
    "zeroday": ProviderSchema(
        cve_fields=("cve_id",),
        published_fields=("disclosed_date",),
        updated_fields=("patched_date",),
    ),
    "zimbra": ProviderSchema(
        identity_fields=("version",),
        title_fields=("title",),
        published_fields=("release_date",),
        source_fields=("reference_links",),
    ),
}


def canonical_cve_id(value: Any) -> str | None:
    code = normalize_cve_code(str(value)) if value not in (None, "") else None
    return f"CVE-{code}" if code else None


def build_v2_document(record: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    provider = str(record.get("type") or record.get("provider") or "").strip().lower()
    code = str(record.get("code") or "").strip()
    if provider not in PROVIDER_SCHEMAS:
        raise ValueError(f"unknown provider for schema v2: {provider!r}")
    if not code:
        raise ValueError("code is required for MongoDB sync")

    legacy_record = dict(record)
    legacy_record["type"] = provider
    raw_details = record.get("details")
    if isinstance(raw_details, dict) and isinstance(raw_details.get(provider), dict):
        detail = dict(raw_details[provider])
    elif isinstance(raw_details, dict):
        detail = dict(raw_details)
        legacy_record["details"] = {provider: detail}
    else:
        detail = {}
        legacy_record["details"] = {provider: detail}

    severity = severity_from_record(legacy_record)
    published_at = parse_timestamp(document_published_time(legacy_record))
    updated_at = parse_timestamp(document_updated_time(legacy_record))
    observed_at = parse_timestamp(output.get("scraped_at") or record.get("observed_at"))
    if observed_at is None:
        raise ValueError("scraped_at/observed_at is required and must be a valid timestamp")

    cve_ids = _document_cve_ids(record, detail)
    status = _text(record.get("status"))
    change_type = _change_type(status)

    cleaned_detail = _clean_detail(
        provider,
        detail,
        code=code,
        title=_text(record.get("title")),
        cve_ids=cve_ids,
        severity=severity,
        published_at=published_at,
        updated_at=updated_at,
        source=record.get("source"),
    )
    if status and change_type is None and not _status_is_redundant(status, severity, cleaned_detail):
        cleaned_detail.setdefault("source_status", status)

    document: dict[str, Any] = {
        "_id": f"{provider}:{code}",
        "schema_version": SCHEMA_VERSION,
        "code": code,
        "title": _text(record.get("title")) or code,
        "observed_at": observed_at,
        "details": cleaned_detail,
    }
    if provider != "cve" and cve_ids:
        document["cve_ids"] = cve_ids
    if severity in CANONICAL_SEVERITIES[:-1]:
        document["severity"] = severity
    if change_type:
        document["change_type"] = change_type
    if published_at:
        document["published_at"] = published_at
    if updated_at:
        document["updated_at"] = updated_at

    source = _clean_source(record.get("source") or output.get("source"))
    if source:
        document["source"] = source

    classification = _clean_classification(record.get("classification"))
    if provider == "cve" and classification:
        document["classification"] = classification
    return document


def convert_existing_document(document: dict[str, Any], provider: str) -> dict[str, Any]:
    if document.get("schema_version") == SCHEMA_VERSION:
        validate_v2_document(document, provider)
        return document
    legacy = dict(document)
    legacy["type"] = provider
    if not legacy.get("code") and isinstance(legacy.get("_id"), str):
        _, separator, suffix = legacy["_id"].partition(":")
        legacy["code"] = suffix if separator else legacy["_id"]
    fallback_observed = (
        document.get("scraped_at")
        or document.get("observed_at")
        or document.get("updated_time")
        or document.get("published_time")
        or datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    output = {"scraped_at": fallback_observed}
    converted = build_v2_document(legacy, output)
    converted["_id"] = document.get("_id", converted["_id"])
    if provider == "cve" and isinstance(document.get("classification"), dict):
        converted["classification"] = _clean_classification(document["classification"])
    return converted


def validate_v2_document(document: dict[str, Any], provider: str) -> None:
    if provider not in PROVIDER_SCHEMAS:
        raise ValueError(f"unknown provider: {provider}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("schema_version must be 2")
    if not isinstance(document.get("_id"), str) or not document["_id"]:
        raise ValueError("_id must remain a non-empty stable string")
    present = PROHIBITED_FIELDS.intersection(document)
    if present:
        raise ValueError(f"prohibited schema-v1 fields present: {sorted(present)}")
    if not isinstance(document.get("observed_at"), datetime):
        raise ValueError("observed_at must be a BSON datetime")
    if not isinstance(document.get("details"), dict):
        raise ValueError("details must be an object")
    if provider != "cve" and "classification" in document:
        raise ValueError("classification is only valid in the cve collection")
    if provider == "cve" and "cve_ids" in document:
        raise ValueError("cve collection must derive its CVE identifier from code")
    cve_ids = document.get("cve_ids", [])
    if len(cve_ids) != len(set(cve_ids)):
        raise ValueError("cve_ids must contain unique values")
    for value in cve_ids:
        if canonical_cve_id(value) != value:
            raise ValueError(f"invalid canonical CVE identifier: {value!r}")
    for field in ("published_at", "updated_at"):
        if field in document and not isinstance(document[field], datetime):
            raise ValueError(f"{field} must be a BSON datetime")
    severity = document.get("severity")
    if severity is not None and severity not in CANONICAL_SEVERITIES[:-1]:
        raise ValueError(f"invalid severity: {severity!r}")


def mongo_json_schema(provider: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "_id": {"bsonType": "string", "minLength": 1},
        "schema_version": {"bsonType": "int", "enum": [SCHEMA_VERSION]},
        "code": {"bsonType": "string", "minLength": 1},
        "title": {"bsonType": "string", "minLength": 1},
        "severity": {"bsonType": "string", "enum": list(CANONICAL_SEVERITIES[:-1])},
        "change_type": {"bsonType": "string", "enum": ["new", "updated"]},
        "published_at": {"bsonType": "date"},
        "updated_at": {"bsonType": "date"},
        "observed_at": {"bsonType": "date"},
        "source": {
            "bsonType": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"bsonType": "string", "minLength": 1},
                "detail_url": {"bsonType": "string", "minLength": 1},
            },
        },
        "details": {"bsonType": "object"},
    }
    if provider == "cve":
        properties["classification"] = {
            "bsonType": "object",
            "required": ["status"],
            "properties": {
                "status": {
                    "bsonType": "string",
                    "enum": ["classified", "unclassified", "failed", "queued", "processing"],
                },
                "queued_at": {"bsonType": "date"},
                "processing_started_at": {"bsonType": "date"},
                "updated_at": {"bsonType": "date"},
            },
        }
    if provider != "cve":
        properties["cve_ids"] = {
            "bsonType": "array",
            "uniqueItems": True,
            "items": {"bsonType": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
        }
    return {
        "bsonType": "object",
        "required": ["_id", "schema_version", "code", "title", "observed_at", "details"],
        "additionalProperties": False,
        "properties": properties,
    }


def ensure_v2_indexes(collection: Any, provider: str, *, drop_legacy: bool = False) -> None:
    if drop_legacy:
        legacy_names = {
            "type_1_code_1",
            "cve_codes_1",
            "related_cves.cve_code_1",
            "disclosure_date_1",
            "published_time_1",
            "updated_time_1",
            "status_1",
            "severity_1",
        }
        existing = {
            index.get("name")
            for index in collection.list_indexes()
            if isinstance(index, dict) or hasattr(index, "get")
        }
        for name in sorted(legacy_names.intersection(existing)):
            collection.drop_index(name)
    collection.create_index(
        [("observed_at", -1), ("_id", -1)],
        name="observed_desc",
    )
    if provider != "cve":
        collection.create_index(
            [("cve_ids", 1)],
            name="cve_ids",
            partialFilterExpression={"cve_ids.0": {"$exists": True}},
        )
    collection.create_index(
        [("severity", 1), ("observed_at", -1)],
        name="severity_observed",
        partialFilterExpression={"severity": {"$exists": True}},
    )
    collection.create_index(
        [("published_at", -1)],
        name="published_desc",
        partialFilterExpression={"published_at": {"$exists": True}},
    )
    if provider == "cve":
        collection.create_index(
            [("classification.status", 1)],
            name="classification_status",
            partialFilterExpression={"classification.status": {"$exists": True}},
        )


def _document_cve_ids(record: dict[str, Any], detail: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for field in ("cve_ids", "cve_codes", "cve_code"):
        value = record.get(field)
        values.extend(value if isinstance(value, list) else [value])
    values.extend(_detail_cve_values(detail))
    result: list[str] = []
    for value in values:
        cve_id = canonical_cve_id(value)
        if cve_id and cve_id not in result:
            result.append(cve_id)
    return result


def _detail_cve_values(detail: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    for field in ("cve_id", "cve_ids", "cveCode", "cveId"):
        value = detail.get(field)
        values.extend(value if isinstance(value, list) else [value])
    identifiers = detail.get("vulnerability_identifiers")
    if isinstance(identifiers, list):
        values.extend(
            item.get("cve_id")
            for item in identifiers
            if isinstance(item, dict)
        )
    return values


def _clean_detail(
    provider: str,
    detail: dict[str, Any],
    *,
    code: str,
    title: str,
    cve_ids: list[str],
    severity: str | None,
    published_at: datetime | None,
    updated_at: datetime | None,
    source: Any,
) -> dict[str, Any]:
    schema = PROVIDER_SCHEMAS[provider]
    cleaned = _compact(detail)
    for field in ("raw", "raw_tables", "raw_sections"):
        cleaned.pop(field, None)
    for field in schema.volatile_fields:
        _delete_path(cleaned, field)

    comparisons = (
        (schema.identity_fields, lambda value: _same_text(value, code)),
        (schema.title_fields, lambda value: _same_text(value, title)),
        (
            schema.cve_fields,
            lambda value: bool(cve_ids)
            and set(_canonical_cves_from_value(value)).issubset(set(cve_ids)),
        ),
        (
            schema.severity_fields,
            lambda value: bool(severity) and normalize_severity(value) == severity,
        ),
        (
            schema.published_fields,
            lambda value: bool(published_at) and parse_timestamp(value) == published_at,
        ),
        (
            schema.updated_fields,
            lambda value: bool(updated_at) and parse_timestamp(value) == updated_at,
        ),
    )
    for paths, predicate in comparisons:
        for path in paths:
            value = _path(cleaned, path)
            if value not in (None, "", [], {}) and predicate(value):
                _delete_path(cleaned, path)

    source_urls = set(_clean_source(source).values())
    for path in schema.source_fields:
        value = _path(cleaned, path)
        if isinstance(value, str) and value in source_urls:
            _delete_path(cleaned, path)
    return _compact(cleaned)


def _clean_source(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result = {}
    for field in ("url", "detail_url"):
        text = _text(value.get(field))
        if text:
            result[field] = text
    if result.get("url") == result.get("detail_url"):
        result.pop("url", None)
    return result


def _clean_classification(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    status = _text(value.get("status"))
    if status == "classified":
        result = {
            key: value.get(key)
            for key in (
                "status", "vendor", "product", "cpe", "confidence", "method",
                "attempts", "error", "queued_at", "processing_started_at", "updated_at",
            )
        }
    elif status == "unclassified":
        candidate = value.get("candidate") if isinstance(value.get("candidate"), dict) else {}
        result = {
            "status": status,
            "reason": value.get("reason"),
            "confidence": value.get("confidence"),
            "candidate": {
                "vendor": candidate.get("vendor") or value.get("best_vendor"),
                "product": candidate.get("product") or value.get("best_product"),
                "cpe": candidate.get("cpe") or value.get("cpe"),
            },
            "attempts": value.get("attempts"),
            "updated_at": value.get("updated_at") or value.get("classified_at"),
        }
    elif status in {"failed", "queued", "processing"}:
        result = {
            key: value.get(key)
            for key in (
                "status", "error", "attempts", "method", "queued_at",
                "processing_started_at", "updated_at",
            )
        }
    else:
        return {}
    result["dictionary_version"] = (
        value.get("dictionary_version") or value.get("taxonomy_version")
    )
    result["classifier_version"] = SCHEMA_VERSION
    result = _compact(result)
    for field in CLASSIFICATION_DATE_FIELDS:
        if field in result:
            parsed = parse_timestamp(result[field])
            if parsed:
                result[field] = parsed
            else:
                result.pop(field, None)
    return result


def _change_type(status: str) -> str | None:
    folded = status.casefold()
    if folded == "new":
        return "new"
    if folded in {"update", "updated"}:
        return "updated"
    return None


def _status_is_redundant(status: str, severity: str | None, detail: dict[str, Any]) -> bool:
    if severity and normalize_severity(status) == severity:
        return True
    folded = status.strip().casefold()
    return any(
        isinstance(value, str) and value.strip().casefold() == folded
        for value in detail.values()
    )


def _canonical_cves_from_value(value: Any) -> list[str]:
    values: list[Any] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                values.extend(item.values())
            else:
                values.append(item)
    elif isinstance(value, dict):
        values.extend(value.values())
    else:
        values.append(value)
    return [item for raw in values if (item := canonical_cve_id(raw))]


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            compacted = _compact(item)
            if compacted not in (None, "", [], {}):
                result[key] = compacted
        return result
    if isinstance(value, list):
        return [
            compacted
            for item in value
            if (compacted := _compact(item)) not in (None, "", [], {})
        ]
    if isinstance(value, str):
        return value.strip()
    return value


def _path(value: dict[str, Any], path: str) -> Any:
    node: Any = value
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _delete_path(value: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    node: Any = value
    for part in parts[:-1]:
        if not isinstance(node, dict):
            return
        node = node.get(part)
    if isinstance(node, dict):
        node.pop(parts[-1], None)


def _same_text(left: Any, right: Any) -> bool:
    return _text(left).casefold() == _text(right).casefold()


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""
