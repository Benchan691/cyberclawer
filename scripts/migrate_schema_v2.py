from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from vuln_scraper.config import (
    DEFAULT_MONGO_CONFIG_FILE,
    ScraperSettings,
    mongo_collection_for_provider,
)
from vuln_scraper.models import normalize_cve_code, primary_cve_code
from vuln_scraper.mongo import create_mongo_client


@dataclass(slots=True)
class MigrationResult:
    scanned: int = 0
    changed: int = 0
    collisions: list[str] = field(default_factory=list)
    missing_cve_code: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def transform_document(document: dict[str, Any], *, provider_key: str | None = None) -> tuple[dict[str, Any], bool]:
    migrated = dict(document)
    original = dict(document)
    doc_type = str(migrated.get("type") or provider_key or "").strip().lower()
    code = str(migrated.get("code") or "").strip()
    if not doc_type or not code:
        raise ValueError("document requires type/code for schema v2 migration")

    migrated["type"] = doc_type
    migrated["code"] = code
    migrated["_id"] = f"{doc_type}:{code}"
    migrated["cve_code"] = _legacy_primary_cve_code(original)
    migrated.pop("cross_refs", None)
    migrated.setdefault("details", {})
    return migrated, migrated != original


def migrate_collection(collection: Any, *, provider_key: str, apply: bool = False) -> MigrationResult:
    result = MigrationResult()
    for document in collection.find({}):
        result.scanned += 1
        migrated, changed = transform_document(document, provider_key=provider_key)
        identity = str(document.get("_id") or f"{provider_key}:{document.get('code', '')}")
        if migrated.get("cve_code") is None:
            result.missing_cve_code.append(migrated["_id"])
        if not changed:
            continue

        existing = collection.find_one({"_id": migrated["_id"]})
        if existing is not None and str(existing.get("_id")) != str(document.get("_id")):
            result.collisions.append(migrated["_id"])
            continue

        result.changed += 1
        if apply:
            if str(document.get("_id")) == migrated["_id"]:
                collection.replace_one({"_id": migrated["_id"]}, migrated, upsert=True)
            else:
                collection.insert_one(migrated)
                collection.delete_one({"_id": identity})
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Migrate MongoDB vulnerability documents to schema v2.")
    parser.add_argument("--mongo-uri", help="MongoDB URI. Overrides mongodb.toml/env defaults.")
    parser.add_argument("--mongo-db", help="MongoDB database. Overrides mongodb.toml/env defaults.")
    parser.add_argument(
        "--mongo-config",
        type=Path,
        default=DEFAULT_MONGO_CONFIG_FILE,
        help=f"MongoDB config file. Default: {DEFAULT_MONGO_CONFIG_FILE}",
    )
    parser.add_argument("--apply", action="store_true", help="Write changes. Default is dry-run.")
    args = parser.parse_args(argv)

    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_uri=args.mongo_uri,
        mongo_database=args.mongo_db,
        mongo_config_file=args.mongo_config,
    ).normalized()
    client = create_mongo_client(settings.mongo_uri or "")
    try:
        database = client[settings.mongo_database]
        for provider_key in ("avd", "hkcert"):
            collection_name = mongo_collection_for_provider(
                provider_key,
                settings.mongo_config_file,
            )
            result = migrate_collection(
                database[collection_name],
                provider_key=provider_key,
                apply=args.apply,
            )
            mode = "applied" if args.apply else "dry-run"
            print(f"{provider_key}/{collection_name} {mode}: {result.to_dict()}")
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


def _legacy_primary_cve_code(document: dict[str, Any]) -> str | None:
    existing = normalize_cve_code(str(document.get("cve_code"))) if document.get("cve_code") is not None else None
    if existing:
        return existing

    for cross_ref in document.get("cross_refs", []):
        if not isinstance(cross_ref, dict):
            continue
        if str(cross_ref.get("type") or "").casefold() == "cve":
            code = normalize_cve_code(str(cross_ref.get("code")))
            if code:
                return code

    details = document.get("details")
    if isinstance(details, dict):
        for detail in details.values():
            code = primary_cve_code(detail if isinstance(detail, dict) else None)
            if code:
                return code
    return None


if __name__ == "__main__":
    main()
