#!/usr/bin/env python3
"""Publish the configured scraper sources to MongoDB's source_catalog collection."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from vuln_scraper.cli import main as scraper_main


def main(argv: list[str] | None = None) -> None:
    # Resolve .env, mongodb.toml and scrapers.toml relative to this checkout.
    os.chdir(Path(__file__).resolve().parent)
    scraper_main(["sync-source-catalog", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    main()
