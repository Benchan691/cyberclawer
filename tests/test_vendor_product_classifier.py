from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vendor_product_classifier.classifier_daemon import classify_document, scan_once
from vendor_product_classifier.cpe_dictionary import CpeCandidate, CpeDictionaryLookup
from vendor_product_classifier.mongo_utils import current_taxonomy_version
from vendor_product_classifier.cve_cpe import (
    english_description,
    extract_cpe_evidence,
    extract_vendor_product_evidence,
)
from vendor_product_classifier.reclassify_cve import classify_cve_document
from vendor_product_classifier.zero_shot import (
    EmbeddingZeroShotClassifier,
    low_confidence_classification,
    success_classification,
)


FIXTURE = "fixtures/cpe_dictionary_sample.csv"


def config() -> dict[str, Any]:
    return {
        "mongo": {"database": "vulnerabilities", "collections": ["cve"]},
        "cpe_dictionary": {"path": FIXTURE},
        "scanner": {
            "interval_seconds": 300,
            "batch_size": 500,
            "claim_timeout_seconds": 1800,
        },
        "worker": {"max_attempts": 3},
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

    assert extract_cpe_evidence(document) == [
        "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
        "Cisco IOS XE",
    ]


def test_extract_vendor_product_evidence_from_structured_and_text_fields() -> None:
    document = {
        "title": "Cisco IOS XE vulnerability",
        "details": {
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
        },
    }

    evidence = extract_vendor_product_evidence(document)

    assert any(item.source == "cve.configurations" and item.cpe for item in evidence)
    assert any(item.source == "cve.affected" and item.vendor == "Cisco" for item in evidence)
    assert any(item.source == "title" and item.text == "Cisco IOS XE vulnerability" for item in evidence)
    assert english_description(document["details"]) == "A flaw in Cisco IOS XE."
    assert any(item.source == "cve.description" for item in evidence)


def test_dictionary_lookup_matches_vendor_product_and_title() -> None:
    lookup = CpeDictionaryLookup(dictionary_path=FIXTURE)

    pair_hit = lookup.lookup(
        extract_vendor_product_evidence(
            {"details": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]}}
        )
    )
    assert pair_hit is not None
    assert pair_hit.match_type == "vendor_product"
    assert pair_hit.candidate.vendor == "Cisco"

    title_hit = lookup.lookup(extract_vendor_product_evidence({"title": "Cisco IOS XE vulnerability"}))
    assert title_hit is not None
    assert title_hit.match_type == "text"


def test_classify_cve_document_uses_dictionary_without_zero_shot() -> None:
    document = {
        "_id": "cve:2026-1000",
        "details": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]},
    }

    classification = classify_cve_document(document, config(), use_zero_shot=False)

    assert classification["status"] == "classified"
    assert classification["method"] == "dictionary"
    assert classification["vendor"] == "Cisco"
    assert classification["product"] == "IOS XE"


def test_classify_cve_document_marks_dictionary_miss_unclassified_without_zero_shot() -> None:
    document = {"_id": "cve:2026-1000"}

    classification = classify_cve_document(document, config(), use_zero_shot=False)

    assert classification["status"] == "unclassified"
    assert classification["reason"] == "dictionary miss"


def test_classify_cve_document_matches_redhat_cpe22_affected_cpes() -> None:
    document = {
        "_id": "cve:2026-53701",
        "title": "CVE-2026-53701",
        "details": {
            "affected": [
                {
                    "vendor": "Red Hat",
                    "product": "Red Hat Enterprise Linux 10",
                    "cpes": ["cpe:/o:redhat:enterprise_linux:10"],
                }
            ],
            "configurations": [],
        },
    }

    classification = classify_cve_document(document, config(), use_zero_shot=False)

    assert classification["status"] == "classified"
    assert classification["method"] == "dictionary"
    assert classification["vendor"] == "Red Hat"
    assert classification["product"] == "Enterprise Linux"


def test_daemon_classifies_via_dictionary() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cve:2026-1000",
                "details": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]},
            }
        ]
    )
    lookup = CpeDictionaryLookup(dictionary_path=FIXTURE)

    stats, _, _ = scan_once(
        FakeDatabase({"cve": collection}),
        config(),
        lookup=lookup,
        zero_shot_classifier=None,
        now=datetime.now(timezone.utc),
    )

    assert stats.classified == 1
    classification = collection.documents["cve:2026-1000"]["classification"]
    assert classification["status"] == "classified"
    assert classification["method"] == "dictionary"
    assert classification["vendor"] == "Cisco"
    assert classification["product"] == "IOS XE"


def test_daemon_skips_unclassified_for_current_dictionary() -> None:
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

    stats, _, _ = scan_once(
        database,
        config(),
        lookup=CpeDictionaryLookup(dictionary_path=FIXTURE),
        now=datetime.now(timezone.utc),
    )

    assert stats.classified == 0
    assert stats.unclassified == 0
    assert stats.skipped_by_reason.get("unclassified_current_dictionary") == 1


def test_zero_shot_classifies_exact_cpe_match() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cve:2026-1000",
                "details": {
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
    zs_config = config()
    zs_config["dictionary_lookup"] = {"enabled": False}

    result = classify_document(
        collection,
        collection.documents["cve:2026-1000"],
        zs_config,
        lookup=None,
        zero_shot_classifier=classifier,
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


def test_zero_shot_marks_low_confidence_matches_unclassified() -> None:
    collection = FakeCollection(
        [{"_id": "cve:low", "details": {"affected": [{"vendor": "Cisco", "product": "IOS XE"}]}}]
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
    zs_config = config()
    zs_config["dictionary_lookup"] = {"enabled": False}

    classification = classify_cve_document(
        collection.documents["cve:low"],
        zs_config,
        zero_shot_classifier=classifier,
        use_zero_shot=True,
    )

    assert classification["status"] == "unclassified"
    assert classification["candidate"]["vendor"] == "Cisco"
    assert classification["dictionary_version"] == "test-dict"
    assert "best_vendor" not in classification


def test_success_and_low_confidence_helpers() -> None:
    success = success_classification(
        {
            "vendor": "Cisco",
            "product": "IOS XE",
            "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
            "confidence": 0.9,
            "method": "zero_shot",
            "dictionary_version": "test",
        }
    )
    assert success["status"] == "classified"
    assert success["method"] == "zero_shot"

    low = low_confidence_classification(
        {
            "vendor": "Cisco",
            "product": "IOS XE",
            "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
            "confidence": 0.2,
            "dictionary_version": "test",
            "reason": "confidence below threshold",
        }
    )
    assert low["status"] == "unclassified"
    assert low["candidate"]["vendor"] == "Cisco"


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
