from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vendor_product_classifier.classifier_scanner import scan_once
from vendor_product_classifier.classifier_worker import process_task
from vendor_product_classifier.rule_alias import RuleAliasMatcher, aliases_fingerprint
from vendor_product_classifier.zero_shot_worker import (
    EmbeddingZeroShotClassifier,
    process_task as process_zero_shot_task,
)


ALIASES = [
    {
        "vendor": "Cisco",
        "product": "Catalyst SD-WAN Manager",
        "aliases": [
            "Cisco Catalyst SD-WAN Manager",
            "Catalyst SD-WAN Manager",
            "Cisco SD-WAN Manager",
            "vManage",
        ],
    },
    {
        "vendor": "Cisco",
        "product": "IOS XE",
        "aliases": ["Cisco IOS XE", "IOS XE", "Cisco IOS-XE"],
    },
    {
        "vendor": "Debian",
        "product": "Linux",
        "aliases": ["Debian Linux", "Debian GNU/Linux"],
    },
    {
        "vendor": "Oracle",
        "product": "Linux",
        "aliases": ["Oracle Linux", "Oracle Enterprise Linux", "OEL"],
    },
]


def config() -> dict[str, Any]:
    return {
        "mongo": {"database": "vulnerabilities", "collections": ["cisco"]},
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
        "zero_shot": {
            "enabled": True,
            "model_name": "test-model",
            "confidence_threshold": 0.78,
        },
    }


def matcher(aliases: list[dict[str, Any]] | None = None) -> RuleAliasMatcher:
    return RuleAliasMatcher.from_aliases(aliases or ALIASES)


def test_cisco_catalyst_sdwan_manager_from_strong_field() -> None:
    document = {
        "_id": "cisco:cisco-sa-example",
        "details": {"cisco": {"product_names": ["Cisco Catalyst SD-WAN Manager"]}},
    }

    match = matcher().match_document(document)

    assert match is not None
    assert match.vendor == "Cisco"
    assert match.product == "Catalyst SD-WAN Manager"
    assert match.method == "rule_alias_strong"


def test_cisco_ios_xe_from_title() -> None:
    document = {
        "_id": "cisco:ios-xe",
        "title": "Cisco IOS XE Software command injection vulnerability",
        "details": {"cisco": {}},
    }

    match = matcher().match_document(document)

    assert match is not None
    assert match.vendor == "Cisco"
    assert match.product == "IOS XE"
    assert match.method == "rule_alias_weak"


def test_oracle_linux_does_not_match_debian_linux() -> None:
    document = {
        "_id": "cve:oracle",
        "title": "Oracle Linux security update",
        "details": {"cve": {}},
    }

    match = matcher().match_document(document)

    assert match is not None
    assert match.vendor == "Oracle"
    assert match.product == "Linux"


def test_generic_linux_alias_alone_is_ignored() -> None:
    local_matcher = matcher(
        [
            {
                "vendor": "Generic",
                "product": "Linux",
                "aliases": ["Linux"],
            }
        ]
    )
    document = {
        "_id": "cve:linux",
        "title": "Linux kernel vulnerability",
        "details": {"cve": {}},
    }

    assert local_matcher.match_document(document) is None


def test_real_alias_file_includes_expanded_vendor_product_taxonomy() -> None:
    real_matcher = RuleAliasMatcher.from_file()
    cases = [
        (
            {
                "_id": "msrc:windows-server",
                "title": "Microsoft Windows Server elevation of privilege vulnerability",
                "details": {"msrc": {}},
            },
            "Microsoft",
            "Windows Server",
        ),
        (
            {
                "_id": "paloalto:globalprotect",
                "details": {
                    "paloalto": {
                        "affected_products": [
                            "Palo Alto Networks GlobalProtect app before 6.2.7"
                        ]
                    }
                },
            },
            "Palo Alto Networks",
            "GlobalProtect",
        ),
        (
            {
                "_id": "cisco:nx-os",
                "title": "Cisco NX-OS Software command injection vulnerability",
                "details": {"cisco": {}},
            },
            "Cisco",
            "NX-OS",
        ),
        (
            {
                "_id": "redhat:rhel",
                "title": "Red Hat Enterprise Linux kernel security update",
                "details": {"cve": {}},
            },
            "Red Hat",
            "Enterprise Linux",
        ),
        (
            {
                "_id": "cnnvd:chrome",
                "details": {
                    "cnnvd": {
                        "affectedProduct": "Chrome Desktop\r\nChromium",
                        "vulDesc": "Google Chrome contains a use after free vulnerability.",
                    }
                },
            },
            "Google",
            "Chrome",
        ),
        (
            {
                "_id": "hkcert:android",
                "title": "Multiple vulnerabilities in Android",
                "details": {"hkcert": {"summary": "Android security bulletin"}},
            },
            "Google",
            "Android",
        ),
        (
            {
                "_id": "cve:adobe-reader",
                "title": "Adobe Acrobat Reader arbitrary code execution vulnerability",
                "details": {"cve": {}},
            },
            "Adobe",
            "Acrobat Reader",
        ),
        (
            {
                "_id": "qnap:qts",
                "title": "QNAP QTS and QuTS hero command injection vulnerability",
                "details": {"qianxin": {}},
            },
            "QNAP Systems",
            "QuTS hero",
        ),
        (
            {
                "_id": "nvidia:driver",
                "title": "NVIDIA GPU Display Driver privilege escalation vulnerability",
                "details": {"cve": {}},
            },
            "NVIDIA",
            "GPU Display Driver",
        ),
        (
            {
                "_id": "redhat:openshift",
                "title": "Red Hat OpenShift Container Platform security update",
                "details": {"cve": {}},
            },
            "Red Hat",
            "OpenShift Container Platform",
        ),
        (
            {
                "_id": "tplink:omada",
                "title": "TP-Link Omada SDN Controller authentication bypass vulnerability",
                "details": {"cve": {}},
            },
            "TP-Link",
            "Omada",
        ),
        (
            {
                "_id": "msrc:malware-protection-engine",
                "title": "Microsoft Malware Protection Engine remote code execution vulnerability",
                "details": {"msrc": {}},
            },
            "Microsoft",
            "Malware Protection Engine",
        ),
    ]

    for document, vendor, product in cases:
        match = real_matcher.match_document(document)
        assert match is not None
        assert (match.vendor, match.product) == (vendor, product)


def test_real_alias_file_falls_back_to_vendor_only_when_product_is_unknown() -> None:
    real_matcher = RuleAliasMatcher.from_file()
    document = {
        "_id": "msrc:unknown-microsoft-component",
        "title": "Microsoft Security Component privilege escalation vulnerability",
        "details": {"msrc": {}},
    }

    assert real_matcher.match_document(document) is None
    match = real_matcher.match_vendor_document(document)

    assert match is not None
    assert match.vendor == "Microsoft"
    assert match.product == ""
    assert match.method == "rule_alias_vendor"


def test_scanner_skips_unclassified_for_current_taxonomy() -> None:
    current_taxonomy = aliases_fingerprint()
    database = FakeDatabase(
        {
            "cisco": FakeCollection(
                [
                    {
                        "_id": "cisco:current-unclassified",
                        "classification": {
                            "status": "unclassified",
                            "taxonomy_version": current_taxonomy,
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


def test_scanner_requeues_unclassified_when_taxonomy_changed() -> None:
    database = FakeDatabase(
        {
            "cisco": FakeCollection(
                [
                    {
                        "_id": "cisco:old-unclassified",
                        "classification": {
                            "status": "unclassified",
                            "taxonomy_version": "old-taxonomy",
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

    assert queued == 1
    assert published[0][0] == "intake"
    assert published[0][1]["document_id"] == "cisco:old-unclassified"
    classification = database["cisco"].documents["cisco:old-unclassified"]["classification"]
    assert classification["status"] == "queued"
    assert classification["taxonomy_version"] == aliases_fingerprint()


def test_scanner_skips_vendor_only_for_current_taxonomy() -> None:
    current_taxonomy = aliases_fingerprint()
    database = FakeDatabase(
        {
            "cisco": FakeCollection(
                [
                    {
                        "_id": "cisco:vendor-only",
                        "classification": {
                            "vendor": "Microsoft",
                            "status": "vendor_only",
                            "taxonomy_version": current_taxonomy,
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


def test_scanner_does_not_queue_already_classified_documents() -> None:
    database = FakeDatabase(
        {
            "cisco": FakeCollection(
                [
                    {
                        "_id": "cisco:classified",
                        "classification": {
                            "vendor": "Cisco",
                            "product": "IOS XE",
                            "status": "classified",
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


def test_worker_updates_mongo_classification_when_rule_match_succeeds() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cisco:ios-xe",
                "title": "Cisco IOS XE Software vulnerability",
                "details": {"cisco": {}},
            }
        ]
    )
    database = FakeDatabase({"cisco": collection})

    result = process_task(
        database,
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cisco",
            "document_id": "cisco:ios-xe",
            "attempt": 0,
        },
        matcher(),
        config(),
        publish=lambda *_: None,
    )

    assert result == "classified"
    classification = collection.documents["cisco:ios-xe"]["classification"]
    assert classification["vendor"] == "Cisco"
    assert classification["product"] == "IOS XE"
    assert classification["status"] == "classified"
    assert classification["method"] == "rule_alias_weak"


def test_worker_sends_unmatched_documents_to_zero_shot_queue() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cisco:unknown",
                "title": "Unknown appliance vulnerability",
                "details": {"cisco": {}},
            }
        ]
    )
    database = FakeDatabase({"cisco": collection})
    published: list[tuple[str, dict[str, Any]]] = []

    result = process_task(
        database,
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cisco",
            "document_id": "cisco:unknown",
            "attempt": 0,
        },
        matcher(),
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
    )

    assert result == "pending_zero_shot"
    assert collection.documents["cisco:unknown"]["classification"]["status"] == "pending_zero_shot"
    assert published == [
        (
            "zero",
            {
                "task_type": "vendor_product_zero_shot",
                "collection": "cisco",
                "document_id": "cisco:unknown",
                "attempt": 0,
                "created_at": published[0][1]["created_at"],
            },
        )
    ]


def test_worker_saves_vendor_only_when_vendor_matches_but_product_does_not() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cisco:microsoft-unknown",
                "title": "Microsoft Security Component privilege escalation vulnerability",
                "details": {"cisco": {}},
            }
        ]
    )
    database = FakeDatabase({"cisco": collection})
    published: list[tuple[str, dict[str, Any]]] = []

    result = process_task(
        database,
        None,
        {
            "task_type": "vendor_product_classification",
            "collection": "cisco",
            "document_id": "cisco:microsoft-unknown",
            "attempt": 0,
        },
        RuleAliasMatcher.from_file(),
        config(),
        publish=lambda _channel, queue, task: published.append((queue, task)),
    )

    assert result == "vendor_only"
    assert published == []
    classification = collection.documents["cisco:microsoft-unknown"]["classification"]
    assert classification["vendor"] == "Microsoft"
    assert classification["status"] == "vendor_only"
    assert classification["method"] == "rule_alias_vendor"
    assert "product" not in classification


def test_zero_shot_worker_classifies_mocked_high_similarity_match() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cisco:semantic",
                "title": "vManage controller command injection vulnerability",
                "details": {"cisco": {"summary": "SD-WAN management controller issue"}},
            }
        ]
    )
    database = FakeDatabase({"cisco": collection})
    classifier = EmbeddingZeroShotClassifier(
        model_name="fake",
        confidence_threshold=0.78,
        aliases=ALIASES,
        model=FakeEmbeddingModel(),
    )
    classifier._label_embeddings = [
        [0.99, 0.01],
        [0.10, 0.90],
        [0.10, 0.80],
        [0.10, 0.70],
        [0.10, 0.60],
        [0.10, 0.50],
        [0.10, 0.40],
        [0.10, 0.30],
    ][: len(classifier.labels)]

    result = process_zero_shot_task(
        database,
        None,
        {
            "task_type": "vendor_product_zero_shot",
            "collection": "cisco",
            "document_id": "cisco:semantic",
            "attempt": 0,
        },
        classifier,
        config(),
    )

    assert result == "classified"
    classification = collection.documents["cisco:semantic"]["classification"]
    assert classification["vendor"] == "Cisco"
    assert classification["product"] == "Catalyst SD-WAN Manager"
    assert classification["method"] == "zero_shot_embedding"
    assert classification["confidence"] >= 0.78


def test_zero_shot_worker_marks_low_confidence_matches_unclassified() -> None:
    collection = FakeCollection(
        [
            {
                "_id": "cisco:low",
                "title": "Unknown appliance vulnerability",
                "details": {"cisco": {"summary": "Unknown appliance issue"}},
            }
        ]
    )
    database = FakeDatabase({"cisco": collection})
    classifier = StaticZeroShotClassifier(
        {
            "classified": False,
            "vendor": "Cisco",
            "product": "IOS XE",
            "confidence": 0.22,
            "matched_alias": "Cisco IOS XE",
            "matched_text": "Unknown appliance vulnerability",
            "reason": "confidence below threshold",
        }
    )

    result = process_zero_shot_task(
        database,
        None,
        {
            "task_type": "vendor_product_zero_shot",
            "collection": "cisco",
            "document_id": "cisco:low",
            "attempt": 0,
        },
        classifier,
        config(),
    )

    assert result == "unclassified"
    classification = collection.documents["cisco:low"]["classification"]
    assert classification["status"] == "unclassified"
    assert classification["method"] == "zero_shot_embedding"
    assert classification["reason"] == "confidence below threshold"
    assert classification["best_vendor"] == "Cisco"


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
            if key == "classification":
                document["classification"] = copy.deepcopy(value)
            else:
                document[key] = copy.deepcopy(value)


class FakeDatabase:
    def __init__(self, collections: dict[str, FakeCollection]) -> None:
        self.collections = collections

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections[name]


class FakeEmbeddingModel:
    def encode(self, texts: list[str], **_: Any) -> list[list[float]]:
        return [[1.0, 0.0] for _ in texts]


class StaticZeroShotClassifier:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def classify(self, _document: dict[str, Any]) -> dict[str, Any]:
        return dict(self.result)
