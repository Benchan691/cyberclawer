from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vuln_scraper.client import ScraperClient
from vuln_scraper.config import DEFAULT_MONGO_CONFIG_FILE, ScraperSettings, mongo_collection_for_provider
from vuln_scraper.models import ListEntry, VulnerabilityId, primary_cve_code
from vuln_scraper.mongo import create_mongo_client
from vuln_scraper.scrapers.qianxin import QianxinProvider


@dataclass(slots=True)
class RemakeResult:
    scanned: int = 0
    refreshed: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def remake_qianxin_documents(
    collection: Any,
    *,
    settings: ScraperSettings,
    apply: bool = False,
    client_factory: type[ScraperClient] = ScraperClient,
) -> RemakeResult:
    provider = QianxinProvider()
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
                )
            except Exception as exc:
                result.errors.append({"identity": identity, "error": str(exc)})
                continue

            if not _document_needs_update(document, updated):
                result.skipped += 1
                continue

            result.refreshed += 1
            if apply:
                collection.replace_one({"_id": updated["_id"]}, updated, upsert=True)

    return result


async def _refresh_document(
    document: dict[str, Any],
    *,
    client: ScraperClient,
    provider: QianxinProvider,
    scraped_at: str,
) -> dict[str, Any]:
    updated = dict(document)
    entry = _entry_from_document(document, provider=provider)
    detail_url = _detail_url(document, provider=provider)
    request = provider.detail_json_request(entry, detail_url=detail_url)
    response = await _fetch_json_request(client, request)
    detail = provider.parse_detail(response.data).to_dict()
    detail = provider.finalize_detail(detail, entry=entry, detail_url=detail_url)

    details = dict(updated.get("details") or {}) if isinstance(updated.get("details"), dict) else {}
    details["qianxin"] = detail
    updated["details"] = details
    updated["cve_code"] = primary_cve_code(detail)
    if detail.get("title"):
        updated["title"] = detail["title"]
    source = dict(updated.get("source") or {}) if isinstance(updated.get("source"), dict) else {}
    source["detail_url"] = detail_url
    source.setdefault("provider", provider.key)
    source.setdefault("url", provider.source_url)
    updated["source"] = source
    updated["scraped_at"] = scraped_at
    return updated


async def _fetch_json_request(client: ScraperClient, request: dict[str, Any]) -> Any:
    method = str(request.get("method") or "GET")
    url = str(request.get("url") or "")
    headers = dict(request.get("headers") or {})
    if method.upper() == "GET" and "json" not in request and "data" not in request:
        return await client.get_json(url, headers=headers)
    return await client.request_json(
        method,
        url,
        headers=headers,
        json_body=request.get("json"),
        data=request.get("data"),
    )


def _document_needs_update(document: dict[str, Any], updated: dict[str, Any]) -> bool:
    return (
        _qianxin_detail(document) != _qianxin_detail(updated)
        or updated.get("cve_code") != document.get("cve_code")
        or updated.get("title") != document.get("title")
    )


def _qianxin_detail(document: dict[str, Any]) -> dict[str, Any]:
    details = document.get("details")
    if not isinstance(details, dict):
        return {}
    qianxin_detail = details.get("qianxin")
    return dict(qianxin_detail) if isinstance(qianxin_detail, dict) else {}


def _entry_from_document(document: dict[str, Any], *, provider: QianxinProvider) -> ListEntry:
    code = str(document.get("code") or "").strip()
    qianxin_detail = _qianxin_detail(document)
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    return ListEntry(
        identity=VulnerabilityId(type="QIANXIN", code=code),
        title=str(document.get("title") or qianxin_detail.get("title") or ""),
        vuln_type=document.get("vuln_type"),
        disclosure_date=document.get("disclosure_date"),
        status=document.get("status"),
        provider=provider.key,
        source_url=source.get("url") if isinstance(source, dict) else None,
        embedded_detail=qianxin_detail or None,
    )


def _detail_url(document: dict[str, Any], *, provider: QianxinProvider) -> str:
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    detail_url = source.get("detail_url") if isinstance(source, dict) else None
    if detail_url:
        return str(detail_url)
    code = str(document.get("code") or "").strip()
    return provider.detail_url(f"QIANXIN-{code}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild qianxin MongoDB documents with the current Qianxin detail schema.",
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
    args = parser.parse_args(argv)

    settings = ScraperSettings(
        mongo_enabled=True,
        mongo_uri=args.mongo_uri,
        mongo_database=args.mongo_db,
        mongo_config_file=args.mongo_config,
    ).for_provider("qianxin").normalized()

    client = create_mongo_client(settings.mongo_uri or "")
    try:
        collection_name = mongo_collection_for_provider("qianxin", settings.mongo_config_file)
        collection = client[settings.mongo_database][collection_name]
        result = asyncio.run(
            remake_qianxin_documents(
                collection,
                settings=settings,
                apply=args.apply,
            )
        )
        mode = "applied" if args.apply else "dry-run"
        print(f"qianxin/{collection_name} {mode}: {result.to_dict()}")
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            close()


if __name__ == "__main__":
    main()
