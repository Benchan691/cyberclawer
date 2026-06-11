from __future__ import annotations

from typing import Any

from vuln_scraper.backfill_severity import backfill_collection_severity, backfill_severity


def test_backfill_collection_severity_updates_missing_or_stale_values() -> None:
    collection = FakeBackfillCollection(
        [
            {
                "_id": "cnnvd:202606-1911",
                "type": "cnnvd",
                "status": "高危",
                "details": {"cnnvd": {"hazardLevel": 2}},
            },
            {
                "_id": "hikvision:1",
                "type": "hikvision",
                "severity": "High",
                "details": {"hikvision": {"severity": "High"}},
            },
            {
                "_id": "cnvd:1",
                "type": "cnvd",
                "status": "中",
                "severity": "中",
                "details": {"cnvd": {"severity": "低"}},
            },
        ]
    )

    scanned, updated, unchanged = backfill_collection_severity(collection)

    assert scanned == 3
    assert updated == 2
    assert unchanged == 1
    assert collection.documents["cnnvd:202606-1911"]["severity"] == "High"
    assert collection.documents["cnvd:1"]["severity"] == "Medium"
    assert collection.documents["hikvision:1"]["severity"] == "High"
    assert ("severity", False) in collection.indexes


def test_backfill_collection_severity_dry_run_does_not_write() -> None:
    collection = FakeBackfillCollection(
        [
            {
                "_id": "cnnvd:1",
                "type": "cnnvd",
                "details": {"cnnvd": {"hazardLevel": 1}},
            }
        ]
    )

    scanned, updated, unchanged = backfill_collection_severity(collection, dry_run=True)

    assert scanned == 1
    assert updated == 1
    assert unchanged == 0
    assert "severity" not in collection.documents["cnnvd:1"]


def test_backfill_severity_skips_missing_collections() -> None:
    database = FakeDatabase(collections={"cnnvd": FakeBackfillCollection([])})

    results = backfill_severity(database, providers=["cnnvd", "hikvision"])

    by_provider = {result.provider: result for result in results}
    assert by_provider["cnnvd"].scanned == 0
    assert by_provider["hikvision"].skipped is True
    assert by_provider["hikvision"].message == "collection missing"


class FakeDatabase:
    def __init__(self, *, collections: dict[str, FakeBackfillCollection]) -> None:
        self._collections = collections

    def list_collections(self, *, filter: dict) -> list[dict[str, str]]:
        return [{"name": name} for name in self._collections]

    def __getitem__(self, name: str) -> FakeBackfillCollection:
        return self._collections[name]


class FakeBackfillCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = {document["_id"]: dict(document) for document in documents}
        self.indexes: list[tuple[Any, bool]] = []
        self.bulk_writes: list[list] = []

    def create_index(self, field: str, unique: bool = False) -> None:
        self.indexes.append((field, unique))

    def find(self, query: dict, projection: dict | None = None):
        for document in self.documents.values():
            yield dict(document)

    def bulk_write(self, updates: list, *, ordered: bool = False) -> None:
        from pymongo import UpdateOne

        self.bulk_writes.append(list(updates))
        for update in updates:
            assert isinstance(update, UpdateOne)
            document_id = update._filter["_id"]
            severity = update._doc["$set"]["severity"]
            self.documents[document_id]["severity"] = severity
