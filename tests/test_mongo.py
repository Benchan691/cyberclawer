import copy
from datetime import datetime, timezone

import pytest

from vuln_scraper.config import ScraperSettings
from vuln_scraper.mongo import (
    build_mongo_document,
    documents_content_match,
    documents_match,
    redact_mongo_uri,
    sync_output_to_mongo,
)


def test_build_mongo_document_requires_type_and_code() -> None:
    with pytest.raises(ValueError):
        build_mongo_document({"title": "missing id"}, output_payload())


def test_build_mongo_document_emits_closed_v2_envelope() -> None:
    document = build_mongo_document(record("2026-10001", cve_code="2026-10001"), output_payload())

    assert document["_id"] == "avd:2026-10001"
    assert document["schema_version"] == 2
    assert document["code"] == "2026-10001"
    assert document["cve_ids"] == ["CVE-2026-10001"]
    assert document["source"] == {"url": "https://example.test"}
    assert document["details"] == {"source_status": "CVE PoC"}
    assert not {"type", "cve_code", "cve_codes", "vuln_type", "status"} & document.keys()


def test_build_mongo_document_sets_normalized_severity() -> None:
    document = build_mongo_document(
        {
            "type": "cnnvd",
            "code": "CNNVD-2026-001",
            "status": "高危",
            "details": {"cnnvd": {"hazardLevel": 2}},
        },
        output_payload(),
    )

    assert document["severity"] == "High"


@pytest.mark.parametrize(
    ("metric_key", "base_severity", "expected"),
    [
        ("cvss_v40", "CRITICAL", "Critical"),
        ("cvss_v31", "HIGH", "High"),
        ("cvss_v30", "MEDIUM", "Medium"),
        ("cvss_v2", "LOW", "Low"),
    ],
)
def test_build_mongo_document_derives_cve_severity_from_normalized_metrics(
    metric_key: str,
    base_severity: str,
    expected: str,
) -> None:
    document = build_mongo_document(
        {
            "type": "cve",
            "code": "2026-10001",
            "title": "CVE severity test",
            "details": {
                "cve": {
                    "metrics": {
                        metric_key: [{"cvssData": {"baseSeverity": base_severity}}]
                    }
                }
            },
        },
        output_payload(),
    )

    assert document["severity"] == expected


def test_sync_inserts_records_and_creates_indexes() -> None:
    collection = FakeCollection()
    settings = ScraperSettings(mongo_enabled=True)

    result = sync_output_to_mongo(
        output_payload([record("AVD-2026-10001")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.inserted == 1
    assert [item[1]["name"] for item in collection.indexes] == [
        "observed_desc", "cve_ids", "severity_observed", "published_desc"
    ]
    assert collection.documents["avd:2026-10001"]["schema_version"] == 2


def test_build_mongo_document_sets_normalized_timestamps() -> None:
    document = build_mongo_document(
        {
            **record("2026-10001"),
            "disclosure_date": "2026-06-18",
        },
        output_payload(),
    )

    assert document["published_at"] == datetime(2026, 6, 17, 16, tzinfo=timezone.utc)
    assert document["updated_at"] == datetime(2026, 6, 17, 16, tzinfo=timezone.utc)


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
    assert "cve_ids" not in collection.documents["avd:2026-10002"]


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


def test_documents_content_match_ignores_observation_metadata() -> None:
    existing = build_mongo_document(record("2026-10001", cve_code="2026-10001"), output_payload())
    existing["observed_at"] = datetime(2026, 1, 1, tzinfo=timezone.utc)
    existing["source"] = {"url": "https://old.example.test"}
    incoming = build_mongo_document(record("2026-10001", cve_code="2026-10001"), output_payload())

    assert documents_match(existing, incoming)
    assert documents_content_match(existing, incoming)


def test_documents_content_match_detects_detail_changes() -> None:
    existing = build_mongo_document(record("2026-10001"), output_payload())
    incoming = build_mongo_document(record("2026-10001", title="updated"), output_payload())

    assert not documents_content_match(existing, incoming)


def test_build_mongo_document_strips_hkcert_views() -> None:
    details = {
        "hkcert": {
            "summary": "Example bulletin",
            "risk_level": "High",
            "views": "1004",
        }
    }
    document = build_mongo_document(hkcert_record("example-bulletin", details=details), output_payload())

    assert "views" not in document["details"]


def test_build_mongo_document_derives_hkcert_cve_codes_from_identifiers() -> None:
    document = build_mongo_document(
        hkcert_record(
            "android-multiple-vulnerabilities",
            details={
                "hkcert": {
                    "vulnerability_identifiers": [
                        {"cve_id": "CVE-2025-48595"},
                        {"cve_id": "CVE-2025-48633"},
                    ]
                }
            },
        ),
        output_payload(),
    )

    assert document["cve_ids"] == ["CVE-2025-48595", "CVE-2025-48633"]


def test_sync_does_not_materialize_related_cve_documents() -> None:
    hkcert_collection = FakeCollection()
    cve_collection = FakeCollection()
    cve_collection.documents["cve:2025-48595"] = {
        "_id": "cve:2025-48595",
        "type": "cve",
        "code": "2025-48595",
    }
    settings = ScraperSettings(mongo_enabled=True)

    result = sync_output_to_mongo(
        output_payload(
            [
                hkcert_record(
                    "android-multiple-vulnerabilities",
                    details={
                        "hkcert": {
                            "vulnerability_identifiers": [
                                {"cve_id": "CVE-2025-48595"},
                                {"cve_id": "CVE-2025-48633"},
                            ]
                        }
                    },
                )
            ]
        ),
        settings,
        client_factory=fake_factory(
            hkcert_collection,
            {"hkcert": hkcert_collection, "cve": cve_collection},
        ),
    )

    assert result.inserted == 1
    document = hkcert_collection.documents["hkcert:android-multiple-vulnerabilities"]
    assert document["cve_ids"] == ["CVE-2025-48595", "CVE-2025-48633"]
    assert "related_cve_ids" not in document
    assert "related_cves" not in document


def test_sync_discards_classification_outside_cve_collection() -> None:
    collection = FakeCollection()
    existing = build_mongo_document(record("2026-10001", title="old"), output_payload())
    existing["classification"] = {"status": "classified", "vendor": "Cisco", "product": "IOS XE"}
    collection.documents["avd:2026-10001"] = existing
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="overwrite")

    result = sync_output_to_mongo(
        output_payload([record("2026-10001", title="new")]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.overwritten == 1
    assert collection.documents["avd:2026-10001"]["title"] == "new"
    assert "classification" not in collection.documents["avd:2026-10001"]


def test_build_mongo_document_strips_raw_detail_fields() -> None:
    document = build_mongo_document(
        {
            "type": "cve",
            "code": "2026-10001",
            "title": "title",
            "details": {
                "cve": {
                    "cve_id": "CVE-2026-10001",
                    "title": "duplicate",
                    "published": "2026-01-01",
                    "vuln_status": "PUBLISHED",
                    "affected_products": ["Cisco IOS XE"],
                    "raw": {"big": "blob"},
                    "affected": [{"vendor": "Cisco", "product": "IOS XE"}],
                }
            },
        },
        output_payload(),
    )

    assert "cve_ids" not in document
    assert document["details"] == {
        "title": "duplicate",
        "affected": [{"vendor": "Cisco", "product": "IOS XE"}]
    }


def test_sync_skips_unchanged_hkcert_when_only_views_change() -> None:
    collection = FakeCollection()
    details = {"hkcert": {"summary": "Example bulletin", "views": "1004"}}
    existing = build_mongo_document(hkcert_record("example-bulletin", details=details), output_payload())
    collection.documents["hkcert:example-bulletin"] = existing
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="overwrite")

    incoming_details = copy.deepcopy(details)
    incoming_details["hkcert"]["views"] = "1005"
    result = sync_output_to_mongo(
        output_payload([hkcert_record("example-bulletin", details=incoming_details)]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.unchanged == 1
    assert result.skipped == 1
    assert result.overwritten == 0
    assert "views" not in collection.documents["hkcert:example-bulletin"]["details"]


def test_documents_content_match_ignores_qianxin_read_num_and_navigation() -> None:
    details = {
        "qianxin": {
            "article_id": "1868",
            "title": "Redis advisory",
            "digest": "Redis Lua advisory summary.",
            "read_num": 24,
            "prev_article": {"id": "1864", "title": "Previous advisory"},
            "next_article": {"id": "1869", "title": "Next advisory"},
            "raw": {"read_num": 24, "prev": {"id": 1864}},
        }
    }
    existing = build_mongo_document(qianxin_record("1868", details=details), output_payload())
    incoming_details = copy.deepcopy(details)
    incoming_details["qianxin"]["read_num"] = 25
    incoming_details["qianxin"]["prev_article"] = {"id": "1865", "title": "Different previous"}
    incoming_details["qianxin"]["next_article"] = {"id": "1870", "title": "Different next"}
    incoming_details["qianxin"]["raw"] = {"read_num": 25, "prev": {"id": 1865}}
    incoming = build_mongo_document(qianxin_record("1868", details=incoming_details), output_payload())

    assert documents_content_match(existing, incoming)
    assert documents_match(existing, incoming)


def test_sync_skips_unchanged_qianxin_when_only_read_num_changes() -> None:
    collection = FakeCollection()
    details = {"qianxin": {"title": "Redis advisory", "read_num": 24}}
    existing = build_mongo_document(qianxin_record("1868", details=details), output_payload())
    collection.documents["qianxin:1868"] = existing
    settings = ScraperSettings(mongo_enabled=True, mongo_conflict="overwrite")

    incoming_details = copy.deepcopy(details)
    incoming_details["qianxin"]["read_num"] = 25
    result = sync_output_to_mongo(
        output_payload([qianxin_record("1868", details=incoming_details)]),
        settings,
        client_factory=fake_factory(collection),
    )

    assert result.unchanged == 1
    assert result.skipped == 1
    assert result.overwritten == 0


def test_sync_skips_unchanged_documents() -> None:
    collection = FakeCollection()
    existing = build_mongo_document(record("2026-10001"), output_payload())
    existing["observed_at"] = datetime(2025, 1, 1, tzinfo=timezone.utc)
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


def hkcert_record(code: str, *, details: dict[str, dict] | None = None, title: str = "title") -> dict:
    return {
        "type": "hkcert",
        "code": code,
        "title": title,
        "status": "Published",
        "details": details or {"hkcert": {"summary": title}},
    }


def qianxin_record(code: str, *, details: dict[str, dict] | None = None, title: str = "title") -> dict:
    return {
        "type": "qianxin",
        "code": code,
        "title": title,
        "status": "Published",
        "details": details or {"qianxin": {"title": title, "digest": title}},
    }


def output_payload(vulnerabilities: list[dict] | None = None) -> dict:
    return {
        "scraped_at": "2026-06-01T00:00:00+00:00",
        "source": {"url": "https://example.test"},
        "vulnerabilities": vulnerabilities or [],
    }


def fake_factory(collection: "FakeCollection", collections: dict[str, "FakeCollection"] | None = None):
    def create_client(uri: str) -> "FakeClient":
        return FakeClient(collection, collections)

    return create_client


class FakeClient:
    def __init__(
        self,
        collection: "FakeCollection",
        collections: dict[str, "FakeCollection"] | None = None,
    ) -> None:
        self.database = FakeDatabase(collection, collections)
        self.closed = False

    def __getitem__(self, name: str) -> "FakeDatabase":
        return self.database

    def close(self) -> None:
        self.closed = True


class FakeDatabase:
    def __init__(
        self,
        collection: "FakeCollection",
        collections: dict[str, "FakeCollection"] | None = None,
    ) -> None:
        self.collection = collection
        self.collections = dict(collections or {})
        for item in [collection, *self.collections.values()]:
            item.database = self

    def __getitem__(self, name: str) -> "FakeCollection":
        return self.collections.get(name, self.collection)


class FakeCollection:
    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}
        self.indexes: list[tuple[object, dict]] = []
        self.database = None

    def create_index(self, field: object, **options) -> None:
        self.indexes.append((field, options))

    def find_one(self, query: dict) -> dict | None:
        for document in self.documents.values():
            if _matches_query(document, query):
                return copy.deepcopy(document)
        return None

    def find(self, query: dict, projection: dict | None = None):
        return [
            copy.deepcopy(document)
            for document in self.documents.values()
            if _matches_query(document, query)
        ]

    def insert_one(self, document: dict) -> None:
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)

    def delete_one(self, query: dict):
        deleted = int(query["_id"] in self.documents)
        self.documents.pop(query["_id"], None)
        return FakeDeleteResult(deleted)


class FakeDeleteResult:
    def __init__(self, deleted_count: int) -> None:
        self.deleted_count = deleted_count


def _matches_query(document: dict, query: dict) -> bool:
    if "$or" in query:
        return any(_matches_query(document, condition) for condition in query["$or"])
    for field, expected in query.items():
        value = _field_value(document, field)
        if isinstance(expected, dict) and "$in" in expected:
            candidates = value if isinstance(value, list) else [value]
            if not any(candidate in expected["$in"] for candidate in candidates):
                return False
        elif isinstance(value, list):
            if expected not in value:
                return False
        elif value != expected:
            return False
    return True


def _field_value(document: dict, field: str):
    value = document
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value
