from __future__ import annotations

import os
from uuid import uuid4

import pytest

from vuln_scraper.migrate_mongo import migrate_mongo, unify_mongo


pytestmark = pytest.mark.skipif(
    not os.environ.get("MONGO_INTEGRATION_URI"),
    reason="set MONGO_INTEGRATION_URI to run real MongoDB integration tests",
)


@pytest.fixture
def database():
    from pymongo import MongoClient

    client = MongoClient(os.environ["MONGO_INTEGRATION_URI"], serverSelectionTimeoutMS=5000)
    name = f"vulnerability_schema_v2_test_{uuid4().hex}"
    database = client[name]
    try:
        yield database
    finally:
        client.drop_database(name)
        client.close()


def legacy_document(provider: str, code: str) -> dict:
    return {
        "_id": f"{provider}:{code}",
        "type": provider,
        "code": code,
        "title": "Integration advisory",
        "cve_code": "CVE-2026-1000",
        "status": "High",
        "scraped_at": "2026-07-23T00:00:00Z",
        "details": {
            provider: {
                "description": "Provider evidence",
                "severity": "High",
                "cve_id": "CVE-2026-1000",
            }
        },
    }


def test_shadow_cutover_installs_validator_indexes_without_views_and_is_rerunnable(database) -> None:
    database["avd"].insert_one(legacy_document("avd", "native-code"))

    results = migrate_mongo(database, collections=["avd"], dry_run=False)

    assert results[0].status == "complete"
    converted = database["avd"].find_one({"_id": "avd:native-code"})
    assert converted["schema_version"] == 2
    assert converted["source"]["provider"] == "avd"
    assert converted["cve_ids"] == ["CVE-2026-1000"]
    assert converted["details"]["description"] == "Provider evidence"
    assert set(database["avd"].index_information()) >= {
        "_id_", "observed_desc", "cve_ids", "severity_observed", "published_desc"
    }
    assert "avd_review" not in database.list_collection_names()

    with pytest.raises(Exception):
        database["avd"].insert_one(
            {
                "_id": "avd:invalid",
                "schema_version": 2,
                "code": "invalid",
                "title": "Invalid",
                "observed_at": "not-a-date",
                "details": {},
            }
        )

    rerun = migrate_mongo(database, collections=["avd"], dry_run=False)
    assert rerun[0].status == "already_v2"
    assert rerun[0].updated == 0


def test_unified_cutover_merges_sources_and_preserves_backups(database) -> None:
    database["avd"].insert_one(legacy_document("avd", "native-code"))
    database["cisco"].insert_one(legacy_document("cisco", "cisco-sa-test"))

    result = unify_mongo(database, dry_run=False)

    assert result.status == "complete"
    assert database["news"].count_documents({}) == 2
    assert database["news"].count_documents({"source.provider": "avd"}) == 1
    assert database["news"].count_documents({"source.provider": "cisco"}) == 1
    assert all(name in database.list_collection_names() for name in result.backup_collections)
