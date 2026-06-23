#!/usr/bin/env python3
"""Authenticate with CNVD and run the CNVD scraper (in-memory cookies, no JSON file)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dataclasses import replace

from vuln_scraper.config import default_scrape_settings
from vuln_scraper.scrapers import get_provider
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers.cnvd.session import CNVDSession, CNVDSessionError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


async def run_cnvd_scrape(
    *,
    data_dir: Path,
    limit: int,
    mongo_enabled: bool,
) -> dict:
    session = CNVDSession.for_data_dir(data_dir)
    await asyncio.to_thread(
        session.ensure_authenticated,
        refresh_cookies=True,
        persist_cookies=False,
    )

    settings = default_scrape_settings(limit=limit, mongo_enabled=mongo_enabled)
    settings = replace(settings, data_dir=data_dir).normalized()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    return await ScraperRunner(
        settings,
        provider=get_provider("cnvd"),
        cnvd_session=session,
    ).run()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CNVD gate bypass + scrape (cookies passed in-memory to the scraper)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Scraper data directory (checkpoints, output)",
    )
    parser.add_argument("--limit", type=int, default=20, help="Max records to scrape")
    parser.add_argument(
        "--no-mongo",
        action="store_true",
        help="Disable MongoDB sync",
    )
    args = parser.parse_args()

    try:
        output = asyncio.run(
            run_cnvd_scrape(
                data_dir=args.data_dir,
                limit=args.limit,
                mongo_enabled=not args.no_mongo,
            )
        )
    except CNVDSessionError as exc:
        log.error("%s", exc)
        sys.exit(1)
    except Exception as exc:
        log.error("CNVD scrape failed: %s", exc)
        sys.exit(1)

    vulnerabilities = output.get("vulnerabilities", [])
    mongo = output.get("mongo_sync") or {}
    print(
        f"cnvd: fetched {len(vulnerabilities)} records; "
        f"inserted={mongo.get('inserted', 0)} "
        f"overwritten={mongo.get('overwritten', 0)} "
        f"skipped={mongo.get('skipped', 0)}"
    )


if __name__ == "__main__":
    main()
