from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import replace

from .catch_up import DEFAULT_MAX_RUNS_PER_PROVIDER
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
    run_parser.add_argument(
        "--proxy",
        default=None,
        help="HTTP(S) proxy URL for scraper outbound traffic (overrides SCRAPER_PROXY).",
    )

    subparsers.add_parser(
        "tui",
        help="Interactive scrape: choose scraper and amount, sync to MongoDB.",
    )

    catch_up_parser = subparsers.add_parser(
        "catch-up",
        help="Scrape and sync each provider repeatedly until MongoDB overlap.",
    )
    catch_up_parser.add_argument(
        "--limit",
        type=int,
        default=MAX_RESULT_LIMIT,
        help=(
            f"Maximum records to scrape per provider/collection across catch-up "
            f"(1-{MAX_RESULT_LIMIT})."
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
    catch_up_parser.add_argument(
        "--proxy",
        default=None,
        help="HTTP(S) proxy URL for scraper outbound traffic (overrides SCRAPER_PROXY).",
    )

    review_parser = subparsers.add_parser(
        "review",
        help="Create or refresh MongoDB review views for one or more providers.",
    )
    review_parser.add_argument(
        "providers",
        nargs="*",
        help="Provider key(s) to refresh. Omit to refresh all configured providers.",
    )

    backfill_parser = subparsers.add_parser(
        "backfill-severity",
        help="Set top-level severity on existing MongoDB vulnerability documents.",
    )
    backfill_parser.add_argument(
        "providers",
        nargs="*",
        help="Provider key(s) to backfill. Omit to backfill all configured providers.",
    )
    backfill_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many documents would change without writing to MongoDB.",
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
        from .providers import get_provider
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
            if args.proxy:
                settings = replace(settings, proxy_url=args.proxy)
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

    if args.command == "tui":
        from .scrape_tui import run_scrape_tui

        run_scrape_tui()
        return

    if args.command == "catch-up":
        from .catch_up import run_catch_up_cycle

        try:
            limit = validate_limit(args.limit)
            settings = default_scrape_settings(limit=limit)
            if args.browser_headed:
                settings = replace(settings, browser_headless=False)
            if args.manual_verification_timeout_seconds is not None:
                settings = replace(
                    settings,
                    manual_verification_timeout_ms=args.manual_verification_timeout_seconds * 1000,
                )
            if args.proxy:
                settings = replace(settings, proxy_url=args.proxy)
            settings = settings.normalized()
        except ValueError as exc:
            parser.error(str(exc))
        run_catch_up_cycle(
            settings,
            include_manual_verification=args.include_manual_verification,
            max_runs_per_provider=args.max_runs_per_provider,
        )
        return

    if args.command == "review":
        from .mongo import create_mongo_client
        from .providers import get_provider
        from .review_template import refresh_review_views

        providers = list(args.providers)
        try:
            for key in providers:
                get_provider(key)
        except KeyError as exc:
            parser.error(str(exc))

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[settings.mongo_database]
            results = refresh_review_views(
                database,
                providers=providers or None,
                mongo_config_file=settings.mongo_config_file,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()

        refreshed = 0
        skipped = 0
        failed = 0
        for result in results:
            if result.refreshed:
                refreshed += 1
                print(
                    f"{result.provider}: refreshed {result.view_name} "
                    f"(viewOn={result.collection_name})"
                )
                continue
            if result.message != "source collection missing":
                failed += 1
                print(f"{result.provider}: failed {result.view_name} ({result.message})")
                continue
            skipped += 1
            print(
                f"{result.provider}: skipped {result.view_name} "
                f"(missing source collection {result.collection_name})"
            )

        print(
            f"review: refreshed={refreshed} skipped={skipped} failed={failed} "
            f"total={len(results)}"
        )
        if failed:
            raise SystemExit(1)
        return

    if args.command == "backfill-severity":
        from .backfill_severity import backfill_severity
        from .mongo import create_mongo_client
        from .providers import get_provider

        providers = list(args.providers)
        try:
            for key in providers:
                get_provider(key)
        except KeyError as exc:
            parser.error(str(exc))

        settings = default_scrape_settings(mongo_enabled=True).normalized()
        client = create_mongo_client(settings.mongo_uri or "")
        try:
            database = client[settings.mongo_database]
            results = backfill_severity(
                database,
                providers=providers or None,
                mongo_config_file=settings.mongo_config_file,
                dry_run=args.dry_run,
            )
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                close()

        scanned = 0
        updated = 0
        unchanged = 0
        skipped = 0
        for result in results:
            if result.skipped:
                skipped += 1
                print(
                    f"{result.provider}: skipped {result.collection_name} ({result.message})"
                )
                continue
            scanned += result.scanned
            updated += result.updated
            unchanged += result.unchanged
            action = "would update" if args.dry_run else "updated"
            print(
                f"{result.provider}: scanned={result.scanned} "
                f"{action}={result.updated} unchanged={result.unchanged} "
                f"(collection={result.collection_name})"
            )

        prefix = "backfill-severity (dry-run)" if args.dry_run else "backfill-severity"
        print(
            f"{prefix}: scanned={scanned} "
            f"{'would_update' if args.dry_run else 'updated'}={updated} "
            f"unchanged={unchanged} skipped={skipped} total={len(results)}"
        )
        return

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
