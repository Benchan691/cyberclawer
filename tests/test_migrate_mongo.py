from datetime import datetime, timezone

import copy

from vuln_scraper.migrate_mongo import (
    build_migration_update,
    cleanup_mongo_backups,
    unify_mongo,
)


def test_migration_builds_v2_and_normalizes_classification() -> None:
    update = build_migration_update(
        {
            "_id": "cve:2026-1000",
            "type": "cve",
            "code": "2026-1000",
            "title": "CVE-2026-1000",
            "cve_code": "CVE-2026-1000",
            "scraped_at": "2026-01-02T00:00:00Z",
            "details": {
                "cve": {
                    "cve_id": "CVE-2026-1000",
                    "title": "provider title",
                    "raw": {"big": "blob"},
                    "affected_products": ["Cisco IOS XE"],
                    "affected": [{"vendor": "Cisco", "product": "IOS XE"}],
                }
            },
            "classification": {
                "status": "unclassified",
                "best_vendor": "Cisco",
                "best_product": "IOS XE",
                "taxonomy_version": "old",
                "classified_at": "2026-01-03T00:00:00Z",
            },
        },
        "cve",
    )

    converted = update["$set"]
    assert converted["schema_version"] == 2
    assert converted["observed_at"] == datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert "cve_ids" not in converted
    assert converted["details"] == {
        "title": "provider title",
        "affected": [{"vendor": "Cisco", "product": "IOS XE"}],
    }
    assert converted["classification"] == {
        "status": "unclassified",
        "candidate": {"vendor": "Cisco", "product": "IOS XE"},
        "updated_at": datetime(2026, 1, 3, tzinfo=timezone.utc),
        "dictionary_version": "old",
        "classifier_version": 2,
    }
    assert set(update["$unset"]) >= {"type", "cve_code", "scraped_at"}


def test_migration_preserves_stable_legacy_id_and_removes_non_cve_classification() -> None:
    update = build_migration_update(
        {
            "_id": "virtual-zeroday-critical-rce",
            "code": "critical-rce",
            "title": "Critical RCE",
            "scraped_at": "2026-01-02T00:00:00Z",
            "classification": {"status": "classified"},
            "details": {"zeroday": {"description": "Evidence"}},
        },
        "zeroday",
    )

    assert "_id" not in update["$set"]
    assert update["$set"]["schema_version"] == 2
    assert update["$set"]["details"] == {"description": "Evidence"}
    assert "classification" in update["$unset"]


class FakeBackup:
    def __init__(self) -> None:
        self.dropped = False

    def drop(self) -> None:
        self.dropped = True


class FakeDatabase:
    def __init__(self, names: list[str]) -> None:
        self.collections = {name: FakeBackup() for name in names}

    def list_collection_names(self) -> list[str]:
        return list(self.collections)

    def __getitem__(self, name: str) -> FakeBackup:
        return self.collections[name]


def test_cleanup_requires_explicit_non_dry_run_and_seven_day_retention() -> None:
    database = FakeDatabase(
        [
            "avd__backup_20260101T000000Z",
            "cve__backup_20260109T000000Z",
            "avd",
        ]
    )
    now = datetime(2026, 1, 10, tzinfo=timezone.utc)

    assert cleanup_mongo_backups(database, now=now) == [
        "avd__backup_20260101T000000Z"
    ]
    assert not database["avd__backup_20260101T000000Z"].dropped

    cleanup_mongo_backups(database, now=now, dry_run=False)
    assert database["avd__backup_20260101T000000Z"].dropped


def test_unify_mongo_dry_run_merges_providers_and_adds_source_provider() -> None:
    database = UnifiedFakeDatabase(
        {
            "avd": [legacy_document("avd", "one")],
            "cve": [legacy_document("cve", "2026-1000")],
        }
    )

    result = unify_mongo(database, dry_run=True)

    assert result.status == "dry_run"
    assert result.scanned == 2
    assert result.inserted == 2
    assert result.source_collections == ["avd", "cve"]
    assert "news" not in database.collections


def test_unify_mongo_cutover_keeps_sources_as_backups_and_removes_only_known_views() -> None:
    database = UnifiedFakeDatabase(
        {
            "avd": [legacy_document("avd", "one")],
            "cve": [legacy_document("cve", "2026-1000")],
            "avd_review": [],
            "cve_review": [],
            "audit_review": [],
        },
        types={
            "avd": "collection",
            "cve": "collection",
            "avd_review": "view",
            "cve_review": "view",
            "audit_review": "view",
        },
    )

    result = unify_mongo(database, dry_run=False)

    assert result.status == "complete"
    assert set(database["news"].documents) == {"avd:one", "cve:2026-1000"}
    assert database["news"].documents["avd:one"]["source"]["provider"] == "avd"
    assert database["news"].documents["cve:2026-1000"]["source"]["provider"] == "cve"
    assert {name.split("__backup_")[0] for name in result.backup_collections} == {"avd", "cve"}
    assert "avd_review" not in database.collections
    assert "cve_review" not in database.collections
    assert "audit_review" in database.collections

    rerun = unify_mongo(database, dry_run=False)
    assert rerun.status == "already_unified"
    assert rerun.backup_collections == []


def test_unify_mongo_rolls_back_source_renames_when_cutover_fails() -> None:
    database = UnifiedFakeDatabase(
        {
            "avd": [legacy_document("avd", "one")],
            "cve": [legacy_document("cve", "2026-1000")],
            "avd_review": [],
        },
        types={"avd":"collection","cve":"collection","avd_review":"view"},
        fail_rename_from="cve",
    )

    result = unify_mongo(database, dry_run=False)

    assert result.status == "failed"
    assert "simulated rename failure" in result.validation_error
    assert set(database.collections) == {"avd", "cve", "avd_review"}
    assert database["avd"].documents["avd:one"]["type"] == "avd"
    assert "news" not in database.collections


def test_unify_mongo_restores_existing_target_when_shadow_promotion_fails() -> None:
    existing_news = {
        "_id": "hkcert:existing",
        "schema_version": 2,
        "code": "existing",
        "title": "Existing unified news",
        "observed_at": datetime(2026, 9, 21, tzinfo=timezone.utc),
        "source": {"provider": "hkcert"},
        "details": {"description": "Existing"},
    }
    database = UnifiedFakeDatabase(
        {
            "news": [existing_news],
            "avd": [legacy_document("avd", "one")],
        },
        fail_shadow_promotion=True,
    )

    result = unify_mongo(database, dry_run=False)

    assert result.status == "failed"
    assert set(database.collections) == {"news", "avd"}
    assert database["news"].documents == {"hkcert:existing": existing_news}
    assert database["avd"].documents["avd:one"]["type"] == "avd"


def test_unify_mongo_supports_explicit_custom_legacy_collection() -> None:
    database = UnifiedFakeDatabase(
        {"legacy_alerts": [legacy_document("hkcert", "bulletin-one")]}
    )

    result = unify_mongo(
        database,
        source_collections=["legacy_alerts"],
        dry_run=False,
    )

    assert result.status == "complete"
    assert database["news"].documents["hkcert:bulletin-one"]["source"]["provider"] == "hkcert"
    assert any(name.startswith("legacy_alerts__backup_") for name in database.collections)


def test_unify_mongo_refuses_to_delete_physical_review_collection() -> None:
    database = UnifiedFakeDatabase(
        {
            "avd": [legacy_document("avd", "one")],
            "avd_review": [{"_id": "important"}],
        }
    )

    result = unify_mongo(database, dry_run=False)

    assert result.status == "failed"
    assert "physical review collections" in result.validation_error
    assert "avd_review" in database.collections


def legacy_document(provider: str, code: str) -> dict:
    return {
        "_id": f"{provider}:{code}",
        "type": provider,
        "code": code,
        "title": f"{provider} advisory",
        "scraped_at": "2026-09-22T00:00:00Z",
        "details": {provider: {"description": "Migration evidence"}},
    }


class UnifiedFakeCollection:
    def __init__(
        self,
        database: "UnifiedFakeDatabase",
        name: str,
        documents: list[dict] | None = None,
    ) -> None:
        self.database = database
        self.name = name
        self.documents = {
            document["_id"]: copy.deepcopy(document)
            for document in (documents or [])
        }
        self.indexes: list[str] = []

    def find(self, query: dict, projection: dict | None = None):
        return [copy.deepcopy(document) for document in self.documents.values()]

    def insert_many(self, documents: list[dict], ordered: bool = True) -> None:
        for document in documents:
            self.documents[document["_id"]] = copy.deepcopy(document)

    def count_documents(self, query: dict) -> int:
        return len(self.documents)

    def create_index(self, fields, **options) -> None:
        self.indexes.append(options["name"])

    def rename(self, target: str, dropTarget: bool = False) -> None:
        self.database.rename(self.name, target)

    def drop(self) -> None:
        self.database.collections.pop(self.name, None)
        self.database.types.pop(self.name, None)


class UnifiedFakeDatabase:
    def __init__(
        self,
        collections: dict[str, list[dict]],
        *,
        types: dict[str, str] | None = None,
        fail_rename_from: str | None = None,
        fail_shadow_promotion: bool = False,
    ) -> None:
        self.collections: dict[str, UnifiedFakeCollection] = {}
        self.types = dict(types or {})
        self.fail_rename_from = fail_rename_from
        self.fail_shadow_promotion = fail_shadow_promotion
        self.failed_once = False
        for name, documents in collections.items():
            self.collections[name] = UnifiedFakeCollection(self, name, documents)
            self.types.setdefault(name, "collection")

    def __getitem__(self, name: str) -> UnifiedFakeCollection:
        return self.collections[name]

    def list_collection_names(self) -> list[str]:
        return list(self.collections)

    def list_collections(self, filter: dict):
        return [
            {"name": name, "type": self.types.get(name, "collection")}
            for name in self.collections
        ]

    def create_collection(self, name: str, **options) -> None:
        self.collections[name] = UnifiedFakeCollection(self, name)
        self.types[name] = "collection"

    def rename(self, source: str, target: str) -> None:
        if source == self.fail_rename_from and not self.failed_once:
            self.failed_once = True
            raise RuntimeError("simulated rename failure")
        if (
            self.fail_shadow_promotion
            and "__unify_" in source
            and target == "news"
            and not self.failed_once
        ):
            self.failed_once = True
            raise RuntimeError("simulated shadow promotion failure")
        collection = self.collections.pop(source)
        collection.name = target
        self.collections[target] = collection
        self.types[target] = self.types.pop(source, "collection")
