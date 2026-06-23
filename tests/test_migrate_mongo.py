from vuln_scraper.migrate_mongo import build_migration_update


def test_migration_unsets_legacy_fields_and_normalizes_classification() -> None:
    update = build_migration_update(
        {
            "_id": "cve:2026-1000",
            "code": "2026-1000",
            "cve_code": "CVE-2026-1000",
            "related_cve_ids": ["cve:2026-1000"],
            "vuln_type": "High",
            "details": {
                "cve": {
                    "cve_id": "CVE-2026-1000",
                    "title": "duplicate",
                    "raw": {"big": "blob"},
                    "affected_products": ["Cisco IOS XE"],
                }
            },
            "classification": {
                "status": "unclassified",
                "best_vendor": "Cisco",
                "best_product": "IOS XE",
                "taxonomy_version": "old",
                "matched_alias": "Cisco IOS XE",
            },
        },
        "cve",
    )

    assert update["$set"]["cve_codes"] == ["2026-1000"]
    assert update["$set"]["classification"] == {
        "status": "unclassified",
        "candidate": {"vendor": "Cisco", "product": "IOS XE"},
        "dictionary_version": "old",
        "classifier_version": 2,
    }
    assert set(update["$unset"]) >= {
        "cve_code",
        "related_cve_ids",
        "vuln_type",
        "details.cve.cve_id",
        "details.cve.title",
        "details.cve.raw",
        "details.cve.affected_products",
    }


def test_migration_removes_classification_outside_cve_collection() -> None:
    update = build_migration_update(
        {"_id": "cisco:test", "classification": {"status": "classified"}},
        "cisco",
    )

    assert update == {"$unset": {"classification": ""}, "$set": {"cve_codes": []}}
