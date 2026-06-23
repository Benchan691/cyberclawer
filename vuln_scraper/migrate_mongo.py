from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .config import DEFAULT_MONGO_CONFIG_FILE, mongo_collections_from_config
from .models import normalize_cve_code


TOP_LEVEL_UNSET = ("cve_code", "related_cve_ids", "vuln_type")
DETAIL_UNSET = ("raw", "raw_tables", "raw_sections")
CVE_DETAIL_UNSET = ("cve_id", "title", "published", "vuln_status", "affected_products")


@dataclass(slots=True)
class MigrationResult:
    collection: str
    scanned: int = 0
    updated: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def migrate_mongo(
    database: Any,
    *,
    collections: list[str] | None = None,
    dry_run: bool = True,
    mongo_config_file: Any = DEFAULT_MONGO_CONFIG_FILE,
) -> list[MigrationResult]:
    names = collections or sorted(set(mongo_collections_from_config(mongo_config_file).values()))
    results: list[MigrationResult] = []
    for name in names:
        result = MigrationResult(collection=name)
        collection = database[name]
        for document in collection.find({}):
            result.scanned += 1
            update = build_migration_update(document, name)
            if not update:
                continue
            result.updated += 1
            if not dry_run:
                collection.update_one({"_id": document["_id"]}, update)
        results.append(result)
    return results


def build_migration_update(document: dict[str, Any], collection_name: str) -> dict[str, Any]:
    unset = {field: "" for field in TOP_LEVEL_UNSET if field in document}
    set_values: dict[str, Any] = {}

    cve_codes = _normalized_cve_codes(document, collection_name)
    if cve_codes != document.get("cve_codes"):
        set_values["cve_codes"] = cve_codes

    details = document.get("details")
    if isinstance(details, dict):
        for provider, detail in details.items():
            if not isinstance(detail, dict):
                continue
            prefix = f"details.{provider}"
            for field in DETAIL_UNSET:
                if field in detail:
                    unset[f"{prefix}.{field}"] = ""
            if provider != "cnvd" and "raw_fields" in detail:
                unset[f"{prefix}.raw_fields"] = ""
            if provider == "cve":
                for field in CVE_DETAIL_UNSET:
                    if field in detail:
                        unset[f"{prefix}.{field}"] = ""

    if "classification" in document:
        migrated = _migrate_classification(document.get("classification"), collection_name)
        if migrated is None:
            unset["classification"] = ""
        elif migrated != document.get("classification"):
            set_values["classification"] = migrated

    update: dict[str, Any] = {}
    if set_values:
        update["$set"] = set_values
    if unset:
        update["$unset"] = unset
    return update


def _normalized_cve_codes(document: dict[str, Any], collection_name: str) -> list[str]:
    values: list[Any] = []
    raw_codes = document.get("cve_codes")
    if isinstance(raw_codes, list):
        values.extend(raw_codes)
    else:
        values.append(raw_codes)
    values.append(document.get("cve_code"))
    detail = (document.get("details") or {}).get("cve") if isinstance(document.get("details"), dict) else None
    if isinstance(detail, dict):
        values.append(detail.get("cve_id"))
    if collection_name == "cve":
        values.append(document.get("code"))

    codes: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in (None, "", [], {}):
            continue
        code = normalize_cve_code(str(value))
        if code and code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _migrate_classification(value: Any, collection_name: str) -> dict[str, Any] | None:
    if collection_name != "cve" or not isinstance(value, dict):
        return None

    status = str(value.get("status") or "").strip()
    updated_at = value.get("updated_at") or value.get("classified_at")
    dictionary_version = value.get("dictionary_version") or value.get("taxonomy_version")
    if status == "classified" and value.get("vendor") and value.get("product"):
        return _compact(
            {
                "status": "classified",
                "vendor": value.get("vendor"),
                "product": value.get("product"),
                "cpe": value.get("cpe"),
                "confidence": value.get("confidence"),
                "dictionary_version": dictionary_version,
                "classifier_version": 2,
                "updated_at": updated_at,
            }
        )
    if status == "unclassified":
        candidate = value.get("candidate") if isinstance(value.get("candidate"), dict) else {}
        candidate = _compact(
            {
                "vendor": candidate.get("vendor") or value.get("best_vendor"),
                "product": candidate.get("product") or value.get("best_product"),
                "cpe": candidate.get("cpe") or value.get("cpe"),
            }
        )
        return _compact(
            {
                "status": "unclassified",
                "reason": value.get("reason"),
                "confidence": value.get("confidence"),
                "candidate": candidate or None,
                "dictionary_version": dictionary_version,
                "classifier_version": 2,
                "updated_at": updated_at,
            }
        )
    if status == "failed":
        return _compact(
            {
                "status": "failed",
                "error": value.get("error"),
                "attempts": value.get("attempts"),
                "updated_at": value.get("updated_at"),
                "classifier_version": 2,
            }
        )
    return None


def _compact(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", {}, [])}
