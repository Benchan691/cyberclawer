from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vendor_product_classifier.classifier_scanner import scan_once
from vendor_product_classifier.classifier_worker import process_task
from vendor_product_classifier.cpe_dictionary import CpeCandidate, CpeDictionaryLookup
from vendor_product_classifier.mongo_utils import current_taxonomy_version
from vendor_product_classifier.cve_cpe import (
    english_description,
    extract_cpe_evidence,
    extract_vendor_product_evidence,
)
from vendor_product_classifier.zero_shot_worker import (
    EmbeddingZeroShotClassifier,
    process_task as process_zero_shot_task,
)


FIXTURE = "fixtures/cpe_dictionary_sample.csv"


def config() -> dict[str, Any]:
    return {
        "mongo": {"database": "vulnerabilities", "collections": ["cve"]},
        "cpe_dictionary": {"path": FIXTURE},
        "queues": {
            "classification_intake": "intake",
            "zero_shot": "zero",
            "dead_letter": "dead",
        },
        "scanner": {
            "interval_seconds": 300,
            "batch_size": 500,
            "claim_timeout_seconds": 1800,
        },
        "worker": {"prefetch_count": 1, "max_attempts": 3},
        "dictionary_lookup": {"enabled": True},
        "zero_shot": {
            "enabled": True,
            "model_name": "test-model",
            "confidence_threshold": 0.78,
        },
    }


def test_extracts_cpe_evidence_from_cve_detail() -> None:
    document = {
        "details": {
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "affected": [{"vendor": "Cisco", "product": "IOS XE"}],
            }
        }
    }

    assert extract_cpe_evidence(document) == [
        "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
        "Cisco IOS XE",
    ]


def test_extract_vendor_product_evidence_from_structured_and_text_fields() -> None:
    document = {
        "title": "Cisco IOS XE vulnerability",
        "details": {
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*"}
                                ]
                            }
                        ]
                    }
                ],
                "affected": [{"vendor": "Cisco", "product": "IOS XE"}],
                "descriptions": [{"lang": "en", "value": "A flaw in Cisco IOS XE."}],
            }
        },
    }

    evidence = extract_vendor_product_evidence(document)

    assert any(item.source == "cve.configurations" and item.cpe for item in evidence)
    assert any(item.source == "cve.affected" and item.vendor == "Cisco" for item in evidence)
    assert any(item.source == "title" and item.text == "Cisco IOS XE vulnerability" for item in evidence)
    assert english_description(document["details"]["cve"]) == "A flaw in Cisco IOS XE."
    assert any(item.source == "cve.description" for item in evidence)


def test_dictionary_lookup_matches_vendor_product_and_title() -> None:
    lookup = CpeDictionaryLookup(dictionary_path=FIXTURE)

    pair_hit = lookup.lookup(
        extract_vendor_product_evidence(
            {"details": {"cve": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]}}}
        )
    )
    assert pair_hit is not None
    assert pair_hit.match_type == "vendor_product"
    assert pair_hit.candidate.vendor == "Cisco"

    title_hit = lookup.lookup(extract_vendor_product_evidence({"title": "Cisco IOS XE vulnerability"}))
    assert title_hit is not None
    assert title_hit.match_type == "text"


def test_classifier_worker_classifies_via_dictionary_without_zero_shot() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cve:2026-1000",
                "details": {"cve": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]}},
            }
        ]
    )
    published: list[tuple[str, dict[str, Any]]] = []

    result = process_task(
        FakeDatabase({"cve": collection}),
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cve",
            "document_id": "cve:2026-1000",
            "attempt": 0,
        },
        None,
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
    )

    assert result == "classified"
    assert published == []
    classification = collection.documents["cve:2026-1000"]["classification"]
    assert classification["status"] == "classified"
    assert classification["method"] == "dictionary"
    assert classification["vendor"] == "Cisco"
    assert classification["product"] == "IOS XE"


def test_classifier_worker_queues_zero_shot_on_dictionary_miss() -> None:
    database = FakeDatabase({"cve": FakeCollection([{"_id": "cve:2026-1000"}])})
    published: list[tuple[str, dict[str, Any]]] = []

    result = process_task(
        database,
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cve",
            "document_id": "cve:2026-1000",
            "attempt": 0,
        },
        None,
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
    )

    assert result == "queued_zero_shot"
    assert published[0][0] == "zero"
    assert published[0][1]["task_type"] == "vendor_product_zero_shot"


def test_scanner_queues_cve_documents() -> None:
    database = FakeDatabase({"cve": FakeCollection([{"_id": "cve:2026-1000"}])})
    published: list[tuple[str, dict[str, Any]]] = []

    queued = scan_once(
        database,
        None,
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
        now=datetime.now(timezone.utc),
    )

    assert queued == 1
    assert published[0][0] == "intake"
    assert published[0][1]["document_id"] == "cve:2026-1000"


def test_scanner_skips_unclassified_for_current_dictionary() -> None:
    database = FakeDatabase(
        {
            "cve": FakeCollection(
                [
                    {
                        "_id": "cve:current-unclassified",
                        "classification": {
                            "status": "unclassified",
                            "dictionary_version": current_taxonomy_version(),
                        },
                    }
                ]
            )
        }
    )
    published: list[tuple[str, dict[str, Any]]] = []

    queued = scan_once(
        database,
        None,
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
        now=datetime.now(timezone.utc),
    )

    assert queued == 0
    assert published == []


def test_classifier_worker_skips_non_cve_documents() -> None:
    result = process_task(
        FakeDatabase({"cisco": FakeCollection([{"_id": "cisco:ios-xe"}])}),
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cisco",
            "document_id": "cisco:ios-xe",
            "attempt": 0,
        },
        None,
        config(),
        publish=lambda *_: None,
    )

    assert result == "skipped_non_cve"


def test_zero_shot_worker_classifies_exact_cpe_match() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cve:2026-1000",
                "details": {
                    "cve": {
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                },
            }
        ]
    )
    classifier = EmbeddingZeroShotClassifier(
        model_name="fake",
        confidence_threshold=0.78,
        candidates=[
            CpeCandidate(
                vendor="Cisco",
                product="IOS XE",
                cpe="cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
                title="Cisco IOS XE",
            )
        ],
    )

    result = process_zero_shot_task(
        FakeDatabase({"cve": collection}),
        None,
        {
            "task_type": "vendor_product_zero_shot",
            "collection": "cve",
            "document_id": "cve:2026-1000",
            "attempt": 0,
        },
        classifier,
        config(),
    )

    assert result == "classified"
    classification = collection.documents["cve:2026-1000"]["classification"]
    assert classification == {
        "status": "classified",
        "vendor": "Cisco",
        "product": "IOS XE",
        "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
        "confidence": 1.0,
        "method": "zero_shot",
        "dictionary_version": "in-memory",
        "updated_at": classification["updated_at"],
        "classifier_version": 2,
    }


def test_zero_shot_worker_marks_low_confidence_matches_unclassified() -> None:
    collection = FakeCollection(
        [{"_id": "cve:low", "details": {"cve": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]}}}]
    )
    classifier = StaticZeroShotClassifier(
        {
            "classified": False,
            "vendor": "Cisco",
            "product": "IOS XE",
            "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
            "confidence": 0.22,
            "dictionary_version": "test-dict",
            "reason": "confidence below threshold",
        }
    )

    result = process_zero_shot_task(
        FakeDatabase({"cve": collection}),
        None,
        {
            "task_type": "vendor_product_zero_shot",
            "collection": "cve",
            "document_id": "cve:low",
            "attempt": 0,
        },
        classifier,
        config(),
    )

    assert result == "unclassified"
    classification = collection.documents["cve:low"]["classification"]
    assert classification["status"] == "unclassified"
    assert classification["candidate"]["vendor"] == "Cisco"
    assert classification["dictionary_version"] == "test-dict"
    assert "best_vendor" not in classification


class FakeCursor:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def limit(self, count: int) -> "FakeCursor":
        self.documents = self.documents[:count]
        return self

    def __iter__(self):
        return iter(copy.deepcopy(self.documents))


class FakeCollection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = {document["_id"]: copy.deepcopy(document) for document in documents}

    def find(self, _query: dict[str, Any]) -> FakeCursor:
        return FakeCursor(list(self.documents.values()))

    def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> None:
        document = self.documents[query["_id"]]
        for key, value in update.get("$set", {}).items():
            document[key] = copy.deepcopy(value)


class FakeDatabase:
    def __init__(self, collections: dict[str, FakeCollection]) -> None:
        self.collections = collections

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections[name]


class StaticZeroShotClassifier:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def classify(self, _document: dict[str, Any]) -> dict[str, Any]:
        return dict(self.result)
