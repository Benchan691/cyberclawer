from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vuln_scraper.cli import build_parser
from vuln_scraper.scrapers import provider_keys
from vuln_scraper.source_catalog import (
    SOURCE_CATALOG_COLLECTION,
    SOURCE_CATALOG_ID,
    configured_source_keys,
    source_catalog_document,
    write_source_catalog,
)


class FakeCollection:
    def __init__(self) -> None:
        self.calls: list[tuple[dict, dict, bool]] = []

    def replace_one(self, filter, replacement, *, upsert=False) -> None:
        self.calls.append((filter, replacement, upsert))


class FakeDatabase:
    def __init__(self) -> None:
        self.collection = FakeCollection()

    def __getitem__(self, name: str) -> FakeCollection:
        assert name == SOURCE_CATALOG_COLLECTION
        return self.collection


def write_config(tmp_path, content: str):
    config = tmp_path / "scrapers.toml"
    config.write_text(content, encoding="utf-8")
    return config


def test_catalog_uses_explicit_catch_up_provider_list(tmp_path) -> None:
    config = write_config(
        tmp_path,
        '[scrapers.catch_up]\nproviders = ["hkcert", "cve"]\n',
    )

    assert configured_source_keys(config) == ["hkcert", "cve"]


@pytest.mark.parametrize(
    "content",
    [
        "[scrapers.catch_up]\n",
        '[scrapers.catch_up]\nproviders = ["all"]\n',
    ],
)
def test_catalog_uses_all_registered_providers_when_list_is_unrestricted(
    tmp_path, content: str
) -> None:
    config = write_config(tmp_path, content)

    assert configured_source_keys(config) == list(provider_keys())


def test_catalog_skips_unknown_configured_provider(tmp_path) -> None:
    config = write_config(
        tmp_path,
        '[scrapers.catch_up]\nproviders = ["missing-provider", "hkcert"]\n',
    )

    assert configured_source_keys(config) == ["hkcert"]


def test_source_catalog_replaces_single_document_atomically() -> None:
    database = FakeDatabase()
    updated_at = datetime(2026, 9, 23, tzinfo=UTC)

    document = write_source_catalog(
        database, ["hkcert", "cve", "cve"], updated_at=updated_at
    )

    assert document == {
        "_id": SOURCE_CATALOG_ID,
        "providers": ["hkcert", "cve"],
        "updated_at": updated_at,
    }
    assert database.collection.calls == [
        ({"_id": SOURCE_CATALOG_ID}, document, True)
    ]


def test_source_catalog_rejects_unregistered_provider() -> None:
    with pytest.raises(ValueError, match="unknown source catalog provider"):
        source_catalog_document(["not-a-scraper"])


def test_cli_exposes_catalog_only_sync_command() -> None:
    args = build_parser().parse_args(["sync-source-catalog"])

    assert args.command == "sync-source-catalog"
