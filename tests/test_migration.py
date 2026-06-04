import copy

from scripts.migrate_schema_v2 import migrate_collection, transform_document


def test_transform_document_uses_first_legacy_cross_ref() -> None:
    migrated, changed = transform_document(
        {
            "_id": "AVD:2026-10001",
            "type": "AVD",
            "code": "2026-10001",
            "cross_refs": [{"type": "CVE", "code": "2026-10001"}],
            "details": {"avd": {}},
        },
        provider_key="avd",
    )

    assert changed
    assert migrated["_id"] == "avd:2026-10001"
    assert migrated["type"] == "avd"
    assert migrated["cve_code"] == "2026-10001"
    assert "cross_refs" not in migrated


def test_transform_document_derives_cve_code_from_detail_fields() -> None:
    migrated, _ = transform_document(
        {
            "_id": "HKCERT:android",
            "type": "HKCERT",
            "code": "android",
            "details": {
                "hkcert": {
                    "vulnerability_identifiers": [
                        {"cve_id": "CVE-2025-48595"},
                        {"cve_id": "CVE-2025-48633"},
                    ]
                }
            },
        },
        provider_key="hkcert",
    )

    assert migrated["_id"] == "hkcert:android"
    assert migrated["cve_code"] == "2025-48595"


def test_transform_document_preserves_existing_cve_code() -> None:
    migrated, changed = transform_document(
        {
            "_id": "avd:2026-10001",
            "type": "avd",
            "code": "2026-10001",
            "cve_code": "2026-10001",
            "details": {"avd": {}},
        },
        provider_key="avd",
    )

    assert not changed
    assert migrated["cve_code"] == "2026-10001"


def test_migrate_collection_dry_run_does_not_write() -> None:
    collection = FakeMigrationCollection(
        [
            {"_id": "AVD:2026-10001", "type": "AVD", "code": "2026-10001", "details": {"avd": {}}},
        ]
    )

    result = migrate_collection(collection, provider_key="avd", apply=False)

    assert result.scanned == 1
    assert result.changed == 1
    assert result.missing_cve_code == ["avd:2026-10001"]
    assert set(collection.documents) == {"AVD:2026-10001"}


def test_migrate_collection_apply_rebuilds_id() -> None:
    collection = FakeMigrationCollection(
        [
            {
                "_id": "AVD:2026-10001",
                "type": "AVD",
                "code": "2026-10001",
                "details": {"avd": {"cve_id": "CVE-2026-10001"}},
            },
        ]
    )

    result = migrate_collection(collection, provider_key="avd", apply=True)

    assert result.changed == 1
    assert set(collection.documents) == {"avd:2026-10001"}
    assert collection.documents["avd:2026-10001"]["cve_code"] == "2026-10001"


def test_migrate_collection_reports_id_collision() -> None:
    collection = FakeMigrationCollection(
        [
            {"_id": "AVD:2026-10001", "type": "AVD", "code": "2026-10001", "details": {"avd": {}}},
            {"_id": "avd:2026-10001", "type": "avd", "code": "2026-10001", "details": {"avd": {}}},
        ]
    )

    result = migrate_collection(collection, provider_key="avd", apply=True)

    assert result.collisions == ["avd:2026-10001"]


class FakeMigrationCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = {document["_id"]: copy.deepcopy(document) for document in documents}

    def find(self, query: dict | None = None):
        return [copy.deepcopy(document) for document in list(self.documents.values())]

    def find_one(self, query: dict) -> dict | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def insert_one(self, document: dict) -> None:
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)

    def delete_one(self, query: dict) -> None:
        self.documents.pop(query["_id"], None)
