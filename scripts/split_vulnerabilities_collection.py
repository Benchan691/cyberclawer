from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from vuln_scraper.config import (
    DEFAULT_MONGO_COLLECTION,
    DEFAULT_MONGO_CONFIG_FILE,
    ScraperSettings,
    mongo_collection_for_provider,
    mongo_collections_from_config,
)
from vuln_scraper.mongo import create_mongo_client


@dataclass(slots=True)
class SplitResult:
    scanned: int = 0
    moved: int = 0
    skipped_existing: int = 0
    unknown_type: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    by_type: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def split_legacy_collection(
    source_collection: Any,
    database: Any,
    *,
    collections_map: dict[str, str],
    apply: bool = False,
) -> SplitResult:
    result = SplitResult()
    for document in source_collection.find({}):
        result.scanned += 1
        doc_type = str(document.get("type") or "").strip().lower()
        if not doc_type:
            result.unknown_type += 1
            continue

        target_name = collections_map.get(doc_type, doc_type)
        stats = result.by_type.setdefault(
            doc_type,
            {"target": target_name, "moved": 0, "skipped_existing": 0},
        )
        identity = document.get("_id")
        if not identity and document.get("code"):
            identity = f"{doc_type}:{document['code']}"

        target = database[target_name]
        existing = target.find_one({"_id": identity}) if identity else None
        if existing is not None:
            result.skipped_existing += 1
            stats["skipped_existing"] += 1
            if apply:
                source_collection.delete_one({"_id": document["_id"]})
            continue

        result.moved += 1
        stats["moved"] += 1
        if apply:
            target.insert_one(document)
            source_collection.delete_one({"_id": document["_id"]})
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Move records from the legacy mixed vulnerabilities collection "
            "into per-provider collections."
        )
    )
    parser.add_argument("--mongo-uri", help="MongoDB URI. Overrides mongodb.toml/env defaults.")
    parser.add_argument("--mongo-db", help="MongoDB database. Overrides mongodb.toml/env defaults.")
    parser.add_argument(
        "--source-collection",
        default=DEFAULT_MONGO_COLLECTION,
        help=f"Legacy mixed collection name. Default: {DEFAULT_MONGO_COLLECTION}",
    )
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
    collections_map = mongo_collections_from_config(settings.mongo_config_file)
    for provider_key in collections_map:
        collections_map[provider_key] = mongo_collection_for_provider(
            provider_key,
            settings.mongo_config_file,
        )

    client = create_mongo_client(settings.mongo_uri or "")
    try:
        database = client[settings.mongo_database]
        source = database[args.source_collection]
        result = split_legacy_collection(
            source,
            database,
            collections_map=collections_map,
            apply=args.apply,
        )
        mode = "applied" if args.apply else "dry-run"
        print(f"{args.source_collection} {mode}: {result.to_dict()}")
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


if __name__ == "__main__":
    main()
