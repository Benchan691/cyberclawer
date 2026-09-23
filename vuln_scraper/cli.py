from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import replace

from .catch_up import CATCH_UP_BATCH_SIZE, CATCH_UP_DEFAULT_LIMIT, DEFAULT_MAX_RUNS_PER_PROVIDER
from .config import MAX_RESULT_LIMIT, default_scrape_settings
from .filters import validate_limit


def _positive_int_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer value: {value!r}") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Scrape vulnerability catalogs into MongoDB.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    run_parser = subparsers.add_parser(
        "run",
        help="Run one scraper once and sync it to MongoDB.",
    )
    run_parser.add_argument(
        "provider",
        help="Provider key to run, for example cnvd.",
    )
    run_parser.add_argument(
        "--limit",
        type=int,
        default=MAX_RESULT_LIMIT,
        help=f"Maximum records to scrape (1-{MAX_RESULT_LIMIT}).",
    )
    run_parser.add_argument(
        "--browser-headed",
        action="store_true",
        help="Open a visible browser window for browser-backed scrapers.",
    )
    run_parser.add_argument(
        "--no-browser-fallback",
        action="store_true",
        help="Disable browser fallback for browser-backed scrapers and use HTTP/cookies only.",
    )
    run_parser.add_argument(
        "--manual-verification-timeout-seconds",
        type=_positive_int_arg,
        default=None,
        help="Maximum time to wait for headed manual verification.",
    )
    catch_up_parser = subparsers.add_parser(
        "catch-up",
        help="Scrape and sync each provider repeatedly until MongoDB overlap.",
    )
    catch_up_parser.add_argument(
        "--limit",
        type=int,
        default=CATCH_UP_DEFAULT_LIMIT,
        help=(
            f"Maximum new records to scrape per provider/collection across all catch-up "
            f"runs (1-{MAX_RESULT_LIMIT})."
        ),
    )
    catch_up_parser.add_argument(
        "--batch-size",
        type=_positive_int_arg,
        default=CATCH_UP_BATCH_SIZE,
        help="Records to scrape per catch-up run before re-checking overlap (default 5).",
    )
    catch_up_parser.add_argument(
        "--days",
        type=_positive_int_arg,
        default=1,
        help=(
            "Calendar days to include ending today (Asia/Hong_Kong). "
            "Default 1 is today only; use 7 for the last week."
        ),
    )
    catch_up_parser.add_argument(
        "--max-runs-per-provider",
        type=_positive_int_arg,
        default=DEFAULT_MAX_RUNS_PER_PROVIDER,
        help="Safety cap on scrape runs per provider (default 100).",
    )
    catch_up_parser.add_argument(
        "--include-manual-verification",
        action="store_true",
        help="Include scrapers that require headed manual browser verification.",
    )
    catch_up_parser.add_argument(
        "--browser-headed",
        action="store_true",
        help="Open a visible browser window for browser-backed scrapers.",
    )
    catch_up_parser.add_argument(
        "--manual-verification-timeout-seconds",
        type=_positive_int_arg,
        default=None,
        help="Maximum time to wait for headed manual verification.",
    )
    subparsers.add_parser(
        "sync-source-catalog",
        help="Publish the configured source list to MongoDB without scraping.",
    )
    migrate_parser = subparsers.add_parser(
        "migrate-mongo",
        help="Clean legacy MongoDB vulnerability documents.",
    )
    migrate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report changes without writing to MongoDB.",
    )
    migrate_parser.add_argument(
        "--target-version",
        type=int,
        default=2,
        help="Target vulnerability schema version (currently 2).",
    )
    migrate_parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip shadow validation before cutover (not recommended).",
    )
    migrate_parser.add_argument(
        "--database",
        default=None,
        help="MongoDB database name override.",
    )

    unify_parser = subparsers.add_parser(
        "unify-mongo",
        help="Merge provider collections into the unified news collection and remove review views.",
    )
    unify_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report the merge without writing to MongoDB.",
    )
    unify_parser.add_argument(
        "--collection",
        default="news",
        help="Target unified collection (default: news).",
    )
    unify_parser.add_argument(
        "--database",
        default=None,
        help="MongoDB database name override.",
    )
    unify_parser.add_argument(
        "--source-collection",
        action="append",
        dest="source_collections",
        default=None,
        help=(
            "Legacy physical collection to merge. Repeat for custom collection "
            "names; omit to discover standard provider collections."
        ),
    )

    cleanup_parser = subparsers.add_parser(
        "cleanup-mongo-backups",
        help="Remove accepted v2 migration backups after the retention period.",
    )
    cleanup_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List eligible backups without removing them.",
    )
    cleanup_parser.add_argument(
        "--older-than-days",
        type=_positive_int_arg,
        default=7,
        help="Only remove backups at least this old (minimum 7 days).",
    )
    cleanup_parser.add_argument(
        "--database",
        default=None,
        help="MongoDB database name override.",
    )

    reclassify_parser = subparsers.add_parser(
        "reclassify-cve",
        help="Re-run vendor/product classification for CVE documents in the unified collection.",
    )
    reclassify_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report changes without writing to MongoDB.",
    )
    reclassify_parser.add_argument(
        "--database",
        default=None,
        help="MongoDB database name override.",
    )
    reclassify_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum CVE documents to scan.",
    )
    reclassify_parser.add_argument(
        "--zero-shot",
        action="store_true",
        help="Run embedding classification when dictionary lookup misses (slow on large collections).",
    )
    return parser


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> None:
    from .env_file import load_project_dotenv

    load_project_dotenv()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        raise SystemExit(2)

    _configure_logging()

    if args.command == "run":
        from .scrapers import get_provider
        from .runner import ScraperRunner

        try:
            limit = validate_limit(args.limit)
            provider = get_provider(args.provider)
            if args.no_browser_fallback:
                provider = replace(provider, browser_fallback=False)
            settings = default_scrape_settings(limit=limit)
            if args.browser_headed:
                settings = replace(settings, browser_headless=False)
            if args.manual_verification_timeout_seconds is not None:
                settings = replace(
                    settings,
                    manual_verification_timeout_ms=args.manual_verification_timeout_seconds * 1000,
                )
            output = asyncio.run(ScraperRunner(settings, provider=provider).run())
        except (KeyError, ValueError) as exc:
            parser.error(str(exc))
        vulnerabilities = output.get("vulnerabilities", [])
        completed = sum(
            1
            for item in vulnerabilities
            if isinstance(item.get("details"), dict)
            and isinstance(item["details"].get(provider.key), dict)
        )
        mongo = output.get("mongo_sync") or {}
        print(
            f"{provider.key}: fetched {len(vulnerabilities)} records "
            f"({completed} with details); "
            f"inserted={mongo.get('inserted', 0)} "
            f"overwritten={mongo.get('overwritten', 0)} "
            f"deleted={mongo.get('deleted', 0)} "
            f"skipped={mongo.get('skipped', 0)} "
            f"conflicts={mongo.get('conflicts', 0)}"
        )
        return

    if args.command == "catch-up":
        from .catch_up import run_catch_up_cycle

        try:
            limit = validate_limit(args.limit)
            batch_size = validate_limit(args.batch_size)
            settings = default_scrape_settings(limit=limit)
            if args.browser_headed:
                settings = replace(settings, browser_headless=False)
            if args.manual_verification_timeout_seconds is not None:
                settings = replace(
                    settings,
                    manual_verification_timeout_ms=args.manual_verification_timeout_seconds * 1000,
                )
            settings = settings.normalized()
        except ValueError as exc:
            parser.error(str(exc))
        run_catch_up_cycle(
            settings,
            include_manual_verification=args.include_manual_verification,
            max_runs_per_provider=args.max_runs_per_provider,
            batch_size=batch_size,
            days=args.days,
        )
        return

    if args.command == "sync-source-catalog":
        from .source_catalog import sync_source_catalog_to_mongo

        try:
            settings = default_scrape_settings(mongo_enabled=True).normalized()
            catalog = sync_source_catalog_to_mongo(settings)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"source-catalog: providers={len(catalog['providers'])}")
        return

    if args.command == "migrate-mongo":
        from .migrate_mongo import migrate_mongo
        from .mongo import create_mongo_client

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[args.database or settings.mongo_database]
            results = migrate_mongo(
                database,
                dry_run=args.dry_run,
                target_version=args.target_version,
                validate=not args.no_validate,
                mongo_config_file=settings.mongo_config_file,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()

        scanned = sum(result.scanned for result in results)
        updated = sum(result.updated for result in results)
        action = "would_update" if args.dry_run else "updated"
        for result in results:
            suffix = (
                f" backup={result.backup_collection}"
                if result.backup_collection
                else ""
            )
            print(
                f"{result.collection}: scanned={result.scanned} "
                f"{action}={result.updated} status={result.status}{suffix}"
            )
        print(f"migrate-mongo: scanned={scanned} {action}={updated} collections={len(results)}")
        return

    if args.command == "unify-mongo":
        from .migrate_mongo import unify_mongo
        from .mongo import create_mongo_client

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[args.database or settings.mongo_database]
            result = unify_mongo(
                database,
                target_collection=args.collection,
                source_collections=args.source_collections,
                dry_run=args.dry_run,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()
        action = "would_merge" if args.dry_run else "merged"
        print(
            f"unify-mongo: sources={','.join(result.source_collections) or '-'} "
            f"scanned={result.scanned} {action}={result.inserted} "
            f"duplicates={result.duplicates} status={result.status}"
        )
        if result.backup_collections:
            print(f"unify-mongo: backups={','.join(result.backup_collections)}")
        if result.validation_error:
            print(f"unify-mongo: error={result.validation_error}")
            raise SystemExit(1)
        return

    if args.command == "cleanup-mongo-backups":
        from .migrate_mongo import cleanup_mongo_backups
        from .mongo import create_mongo_client

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[args.database or settings.mongo_database]
            names = cleanup_mongo_backups(
                database,
                older_than_days=args.older_than_days,
                dry_run=args.dry_run,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()
        action = "eligible" if args.dry_run else "removed"
        for name in names:
            print(f"{action}: {name}")
        print(f"cleanup-mongo-backups: {action}={len(names)}")
        return

    if args.command == "reclassify-cve":
        from pathlib import Path

        from vendor_product_classifier.mongo_utils import load_config as load_classifier_config
        from vendor_product_classifier.reclassify_cve import reclassify_cve

        from .mongo import create_mongo_client

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        classifier_config = load_classifier_config(
            Path(__file__).resolve().parents[1] / "vendor_product_classifier",
            require_secrets=False,
        )
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[args.database or settings.mongo_database]
            stats = reclassify_cve(
                database,
                classifier_config,
                collection_name=settings.mongo_collection or "news",
                dry_run=args.dry_run,
                limit=args.limit,
                use_zero_shot=args.zero_shot,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()

        action = "would_update" if args.dry_run else "updated"
        print(
            f"reclassify-cve: scanned={stats.scanned} {action}={stats.updated} "
            f"unchanged={stats.unchanged} classified={stats.classified} "
            f"unclassified={stats.unclassified} errors={stats.errors}"
        )
        return

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
