import copy

import pytest

from vuln_scraper.config import ScraperSettings
from vuln_scraper.mongo import build_mongo_document, redact_mongo_uri, sync_output_to_mongo


def test_build_mongo_document_requires_type_and_code() -> None:
    with pytest.raises(ValueError):
        build_mongo_document({"title": "missing id"}, output_payload())


def test_build_mongo_document_sets_lowercase_identity_and_cve_code() -> None:
    document = build_mongo_document(record("2026-10001", cve_code="2026-10001"), output_payload())

    assert document["_id"] == "avd:2026-10001"
    assert document["type"] == "avd"
    assert document["code"] == "2026-10001"
    assert document["cve_code"] == "2026-10001"
    assert "cross_refs" not in document
    assert document["source"] == "test-source"


def test_sync_inserts_records_and_creates_indexes() -> None:
    collection = FakeCollection()
    settings = ScraperSettings(mongo_enabled=True)

    result = sync_output_to_mongo(
        output_payload([record("AVD-2026-10001")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.inserted == 1
    assert collection.indexes == [
        ([("type", 1), ("code", 1)], True),
        ("cve_code", False),
        ("disclosure_date", False),
        ("status", False),
    ]
    assert collection.documents["avd:2026-10001"]["type"] == "avd"


def test_sync_stores_all_raw_output_records() -> None:
    collection = FakeCollection()
    settings = ScraperSettings(mongo_enabled=True)

    result = sync_output_to_mongo(
        output_payload(
            [
                record("2026-10001", cve_code="2026-10001"),
                record("2026-10002", cve_code=None),
            ]
        ),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.inserted == 2
    assert set(collection.documents) == {"avd:2026-10001", "avd:2026-10002"}
    assert collection.documents["avd:2026-10002"]["cve_code"] is None


def test_sync_skips_conflicts_when_not_interactive() -> None:
    collection = FakeCollection()
    collection.documents["avd:2026-10001"] = build_mongo_document(
        record("2026-10001", title="old"),
        output_payload(),
    )
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="prompt", mongo_interactive=False)

    result = sync_output_to_mongo(
        output_payload([record("2026-10001", title="new")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.conflicts == 1
    assert result.skipped == 1
    assert collection.documents["avd:2026-10001"]["title"] == "old"


def test_sync_prompt_can_overwrite_conflict(monkeypatch) -> None:
    collection = FakeCollection()
    collection.documents["avd:2026-10001"] = build_mongo_document(
        record("2026-10001", title="old"),
        output_payload(),
    )
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="prompt", mongo_interactive=True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    result = sync_output_to_mongo(
        output_payload([record("2026-10001", title="new")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.conflicts == 1
    assert result.overwritten == 1
    assert collection.documents["avd:2026-10001"]["title"] == "new"


def test_sync_skips_unchanged_documents() -> None:
    collection = FakeCollection()
    existing = build_mongo_document(record("2026-10001"), output_payload())
    existing["scraped_at"] = "older-run"
    collection.documents["avd:2026-10001"] = existing
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="overwrite")

    result = sync_output_to_mongo(
        output_payload([record("2026-10001")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.unchanged == 1
    assert result.skipped == 1
    assert result.overwritten == 0


def test_redact_mongo_uri_hides_password() -> None:
    assert redact_mongo_uri("mongodb://user:secret@localhost:27017/db") == (
        "mongodb://user:***@localhost:27017/db"
    )


def record(code: str, *, cve_code: str | None = None, title: str = "title") -> dict:
    return {
        "type": "avd",
        "code": code.removeprefix("AVD-"),
        "title": title,
        "vuln_type": "CWE-78",
        "status": "CVE PoC",
        "cve_code": cve_code,
        "details": {"avd": {"cve_id": f"CVE-{cve_code}" if cve_code else None}},
    }


def output_payload(vulnerabilities: list[dict] | None = None) -> dict:
    return {
        "scraped_at": "2026-06-01T00:00:00+00:00",
        "source": "test-source",
        "vulnerabilities": vulnerabilities or [],
    }


def fake_factory(collection: "FakeCollection"):
    def create_client(uri: str) -> "FakeClient":
        return FakeClient(collection)

    return create_client


class FakeClient:
    def __init__(self, collection: "FakeCollection") -> None:
        self.collection = collection
        self.closed = False

    def __getitem__(self, name: str) -> "FakeDatabase":
        return FakeDatabase(self.collection)

    def close(self) -> None:
        self.closed = True


class FakeDatabase:
    def __init__(self, collection: "FakeCollection") -> None:
        self.collection = collection

    def __getitem__(self, name: str) -> "FakeCollection":
        return self.collection


class FakeCollection:
    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}
        self.indexes: list[tuple[str, bool]] = []

    def create_index(self, field: str, unique: bool = False) -> None:
        self.indexes.append((field, unique))

    def find_one(self, query: dict) -> dict | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def insert_one(self, document: dict) -> None:
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)
