from datetime import datetime, timezone

from vuln_scraper.migrate_mongo import build_migration_update, cleanup_mongo_backups


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
