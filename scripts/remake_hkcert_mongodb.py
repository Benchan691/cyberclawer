from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vuln_scraper.client import ScraperClient
from vuln_scraper.config import DEFAULT_MONGO_CONFIG_FILE, ScraperSettings, mongo_collection_for_provider
from vuln_scraper.models import primary_cve_code
from vuln_scraper.mongo import create_mongo_client
from vuln_scraper.scrapers.hkcert import HKCERTProvider
from vuln_scraper.scrapers.hkcert.parsers.detail import normalize_hkcert_detail, parse_detail_page


@dataclass(slots=True)
class RemakeResult:
    scanned: int = 0
    refreshed: int = 0
    normalized_only: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def remake_hkcert_documents(
    collection: Any,
    *,
    settings: ScraperSettings,
    apply: bool = False,
    refetch: bool = True,
    client_factory: type[ScraperClient] = ScraperClient,
) -> RemakeResult:
    provider = HKCERTProvider()
    result = RemakeResult()
    scraped_at = datetime.now(timezone.utc).isoformat()

    async with client_factory(
        delay=settings.request_delay,
        retries=settings.retries,
        timeout=settings.timeout,
        proxy=settings.proxy_url,
    ) as client:
        for document in collection.find({}):
            result.scanned += 1
            identity = str(document.get("_id") or "")
            code = str(document.get("code") or "").strip()
            if not code:
                result.errors.append({"identity": identity, "error": "missing code"})
                continue

            try:
                updated = await _refresh_document(
                    document,
                    client=client,
                    provider=provider,
                    scraped_at=scraped_at,
                    refetch=refetch,
                )
            except Exception as exc:
                result.errors.append({"identity": identity, "error": str(exc)})
                continue

            if not _document_needs_update(document, updated, refetch=refetch):
                result.skipped += 1
                continue

            if refetch:
                result.refreshed += 1
            else:
                result.normalized_only += 1

            if apply:
                collection.replace_one({"_id": updated["_id"]}, updated, upsert=True)

    return result


async def _refresh_document(
    document: dict[str, Any],
    *,
    client: ScraperClient,
    provider: HKCERTProvider,
    scraped_at: str,
    refetch: bool,
) -> dict[str, Any]:
    updated = dict(document)
    details = dict(updated.get("details") or {}) if isinstance(updated.get("details"), dict) else {}
    hkcert_detail = dict(details.get("hkcert") or {}) if isinstance(details.get("hkcert"), dict) else {}

    if refetch:
        detail_url = _detail_url(document, provider=provider)
        response = await client.get_html(detail_url)
        hkcert_detail = parse_detail_page(response.html).to_dict()
        source = dict(updated.get("source") or {}) if isinstance(updated.get("source"), dict) else {}
        source["detail_url"] = detail_url
        source.setdefault("provider", provider.key)
        source.setdefault("url", provider.source_url)
        updated["source"] = source
    else:
        hkcert_detail = normalize_hkcert_detail(hkcert_detail)

    details["hkcert"] = hkcert_detail
    updated["details"] = details
    updated["cve_code"] = primary_cve_code(hkcert_detail)
    updated["scraped_at"] = scraped_at
    return updated


def _document_needs_update(document: dict[str, Any], updated: dict[str, Any], *, refetch: bool) -> bool:
    existing_detail = _hkcert_detail(document)
    updated_detail = _hkcert_detail(updated)
    if refetch:
        return (
            existing_detail != updated_detail
            or updated.get("cve_code") != document.get("cve_code")
            or updated.get("scraped_at") != document.get("scraped_at")
        )
    return normalize_hkcert_detail(existing_detail) != existing_detail


def _hkcert_detail(document: dict[str, Any]) -> dict[str, Any]:
    details = document.get("details")
    if not isinstance(details, dict):
        return {}
    hkcert_detail = details.get("hkcert")
    return dict(hkcert_detail) if isinstance(hkcert_detail, dict) else {}


def _detail_url(document: dict[str, Any], *, provider: HKCERTProvider) -> str:
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    detail_url = source.get("detail_url") if isinstance(source, dict) else None
    if detail_url:
        return str(detail_url)
    code = str(document.get("code") or "").strip()
    return provider.detail_url(f"HKCERT-{code}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild hkcert MongoDB documents with the current HKCERT detail schema.",
    )
    parser.add_argument("--mongo-uri", help="MongoDB URI. Overrides mongodb.toml/env defaults.")
    parser.add_argument("--mongo-db", help="MongoDB database. Overrides mongodb.toml/env defaults.")
    parser.add_argument(
        "--mongo-config",
        type=Path,
        default=DEFAULT_MONGO_CONFIG_FILE,
        help=f"MongoDB config file. Default: {DEFAULT_MONGO_CONFIG_FILE}",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes. Default is dry-run.",
    )
    parser.add_argument(
        "--normalize-only",
        action="store_true",
        help="Only convert legacy intro_tables to table without refetching HKCERT pages.",
    )
    args = parser.parse_args(argv)

    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_uri=args.mongo_uri,
        mongo_database=args.mongo_db,
        mongo_config_file=args.mongo_config,
    ).for_provider("hkcert").normalized()

    client = create_mongo_client(settings.mongo_uri or "")
    try:
        collection_name = mongo_collection_for_provider("hkcert", settings.mongo_config_file)
        collection = client[settings.mongo_database][collection_name]
        result = asyncio.run(
            remake_hkcert_documents(
                collection,
                settings=settings,
                apply=args.apply,
                refetch=not args.normalize_only,
            )
        )
        mode = "applied" if args.apply else "dry-run"
        print(f"hkcert/{collection_name} {mode}: {result.to_dict()}")
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


if __name__ == "__main__":
    main()
