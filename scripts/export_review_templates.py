from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vuln_scraper.config import (
    DEFAULT_MONGO_CONFIG_FILE,
    ScraperSettings,
    mongo_collections_from_config,
)
from vuln_scraper.mongo import create_mongo_client
from vuln_scraper.review_template import ensure_review_view, review_view_name


def export_review_templates(
    database: Any,
    *,
    collections_map: dict[str, str],
    provider: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    provider_keys = [provider] if provider else list(collections_map)
    templates: list[dict[str, Any]] = []
    for provider_key in provider_keys:
        collection_name = collections_map.get(provider_key)
        if not collection_name:
            raise KeyError(f"unknown provider: {provider_key}")
        cursor = database[review_view_name(collection_name)].find({})
        if limit is not None:
            cursor = cursor.limit(max(0, limit - len(templates)))
        for document in cursor:
            document.pop("_id", None)
            templates.append(document)
            if limit is not None and len(templates) >= limit:
                return templates
    return templates


def ensure_review_views(
    database: Any,
    *,
    collections_map: dict[str, str],
    provider: str | None = None,
) -> dict[str, str]:
    provider_keys = [provider] if provider else list(collections_map)
    created: dict[str, str] = {}
    for provider_key in provider_keys:
        collection_name = collections_map.get(provider_key)
        if not collection_name:
            raise KeyError(f"unknown provider: {provider_key}")
        if ensure_review_view(database, provider=provider_key, collection_name=collection_name):
            created[collection_name] = review_view_name(collection_name)
    return created


def export_review_templates_by_collection(
    database: Any,
    *,
    collections_map: dict[str, str],
    limit: int | None = None,
) -> dict[str, list[dict[str, Any]]]:
    return {
        collection_name: export_review_templates(
            database,
            collections_map=collections_map,
            provider=provider_key,
            limit=limit,
        )
        for provider_key, collection_name in collections_map.items()
    }


def write_collection_exports(
    exports: dict[str, list[dict[str, Any]]],
    *,
    output_dir: Path,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for collection_name, templates in exports.items():
        safe_name = collection_name.replace("/", "_").replace("\\", "_")
        output_path = output_dir / f"{safe_name}.json"
        _write_json(output_path, templates)
        written[collection_name] = output_path
    return written


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Export MongoDB vulnerabilities as ReviewTemplate JSON.")
    parser.add_argument("--provider", help="Provider key to export. Default: all configured providers.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output JSON file with --provider, or output directory when exporting all providers. "
            "Default: data/review_templates."
        ),
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum documents per collection.")
    parser.add_argument("--mongo-uri", help="MongoDB URI. Overrides mongodb.toml/env defaults.")
    parser.add_argument("--mongo-db", help="MongoDB database. Overrides mongodb.toml/env defaults.")
    parser.add_argument(
        "--mongo-config",
        type=Path,
        default=DEFAULT_MONGO_CONFIG_FILE,
        help=f"MongoDB config file. Default: {DEFAULT_MONGO_CONFIG_FILE}",
    )
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_uri=args.mongo_uri,
        mongo_database=args.mongo_db,
        mongo_config_file=args.mongo_config,
    ).normalized()
    collections_map = mongo_collections_from_config(settings.mongo_config_file)
    if args.provider and args.provider not in collections_map:
        parser.error(f"unknown provider: {args.provider}")

    client = create_mongo_client(settings.mongo_uri or "")
    try:
        database = client[settings.mongo_database]
        created_views = ensure_review_views(
            database,
            collections_map=collections_map,
            provider=args.provider,
        )
        if args.provider:
            collection_name = collections_map[args.provider]
            if collection_name not in created_views:
                raise RuntimeError(f"source collection does not exist: {collection_name}")
            templates = export_review_templates(
                database,
                collections_map=collections_map,
                provider=args.provider,
                limit=args.limit,
            )
            output_path = args.output or Path("data/review_templates") / f"{collection_name}.json"
            _write_json(output_path, templates)
            print(
                f"Exported {len(templates)} ReviewTemplate document(s) "
                f"from {collection_name} to {output_path}"
            )
        else:
            available_map = {
                provider_key: collection_name
                for provider_key, collection_name in collections_map.items()
                if collection_name in created_views
            }
            output_dir = args.output or Path("data/review_templates")
            exports = export_review_templates_by_collection(
                database,
                collections_map=available_map,
                limit=args.limit,
            )
            written = write_collection_exports(exports, output_dir=output_dir)
            total = sum(len(templates) for templates in exports.values())
            print(
                f"Exported {total} ReviewTemplate document(s) from "
                f"{len(written)} collection(s) to {output_dir}"
            )
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


def _write_json(output_path: Path, templates: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(templates, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
