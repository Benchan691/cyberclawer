from __future__ import annotations

import signal
import threading
from dataclasses import dataclass, field
from typing import Any

try:
    from .cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from .logging_utils import log_event
    from .mongo_utils import (
        build_unclassified_query,
        create_mongo_client,
        current_taxonomy_version,
        get_database,
        load_config,
        mark_failed,
        mark_processing,
        queue_decision,
        utc_now,
        write_classification,
    )
    from .reclassify_cve import classify_cve_document
    from .zero_shot import EmbeddingZeroShotClassifier, reload_zero_shot_if_needed
except ImportError:
    from cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from logging_utils import log_event
    from mongo_utils import (
        build_unclassified_query,
        create_mongo_client,
        current_taxonomy_version,
        get_database,
        load_config,
        mark_failed,
        mark_processing,
        queue_decision,
        utc_now,
        write_classification,
    )
    from reclassify_cve import classify_cve_document
    from zero_shot import EmbeddingZeroShotClassifier, reload_zero_shot_if_needed


STOP_EVENT = threading.Event()
COMPONENT = "vendor-product-daemon"


def log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    log_event(COMPONENT, message, level=level, **fields)


@dataclass(slots=True)
class ScanStats:
    scanned: int = 0
    classified: int = 0
    unclassified: int = 0
    skipped: int = 0
    failed: int = 0
    skipped_by_reason: dict[str, int] = field(default_factory=dict)


def _dictionary_path(config: dict[str, Any]) -> str | None:
    value = (config.get("cpe_dictionary") or {}).get("path")
    return str(value) if value else None


def _dictionary_lookup_enabled(config: dict[str, Any]) -> bool:
    return bool((config.get("dictionary_lookup") or {}).get("enabled", True))


def _lookup_from_config(config: dict[str, Any]) -> CpeDictionaryLookup:
    return CpeDictionaryLookup(dictionary_path=_dictionary_path(config))


def _reload_lookup_if_needed(
    lookup: CpeDictionaryLookup | None,
    config: dict[str, Any],
) -> CpeDictionaryLookup | None:
    if not _dictionary_lookup_enabled(config):
        return None
    if lookup is None:
        return _lookup_from_config(config)
    dictionary_version = cpe_fingerprint(_dictionary_path(config))
    if lookup.dictionary_version == dictionary_version:
        return lookup
    log(
        "CPE dictionary changed; reloading lookup index",
        previous_dictionary_version=lookup.dictionary_version,
        dictionary_version=dictionary_version,
    )
    return _lookup_from_config(config)


def _attempt_count(document: dict[str, Any]) -> int:
    classification = document.get("classification")
    if not isinstance(classification, dict):
        return 0
    try:
        return int(classification.get("attempts") or 0)
    except (TypeError, ValueError):
        return 0


def _cursor_with_limit(cursor: Any, batch_size: int) -> Any:
    limit = getattr(cursor, "limit", None)
    if limit is not None:
        return limit(batch_size)
    return cursor


def classify_document(
    collection: Any,
    document: dict[str, Any],
    config: dict[str, Any],
    *,
    lookup: CpeDictionaryLookup | None,
    zero_shot_classifier: EmbeddingZeroShotClassifier | None,
) -> str:
    document_id = str(document.get("_id") or "")
    if not document_id:
        raise ValueError("missing document id")

    attempt = _attempt_count(document) + 1
    max_attempts = int(config["worker"]["max_attempts"])
    use_zero_shot = bool(config.get("zero_shot", {}).get("enabled"))

    mark_processing(collection, document_id, attempt=attempt)
    classification = classify_cve_document(
        document,
        config,
        lookup=lookup,
        zero_shot_classifier=zero_shot_classifier,
        use_zero_shot=use_zero_shot,
    )
    write_classification(collection, document_id, classification)
    status = classification.get("status")
    if status == "classified":
        return "classified"
    if status == "unclassified":
        return "unclassified"
    return str(status or "updated")


def handle_classification_error(
    collection: Any,
    document: dict[str, Any],
    error: Exception,
    config: dict[str, Any],
) -> str:
    document_id = str(document.get("_id") or "")
    attempt = _attempt_count(document) + 1
    max_attempts = int(config["worker"]["max_attempts"])
    if attempt >= max_attempts:
        mark_failed(collection, document_id, error=str(error), attempts=attempt)
        return "failed"
    mark_processing(collection, document_id, attempt=attempt)
    return "retryable"


def scan_collection(
    database: Any,
    config: dict[str, Any],
    collection_name: str,
    *,
    lookup: CpeDictionaryLookup | None,
    zero_shot_classifier: EmbeddingZeroShotClassifier | None,
    now: Any = None,
) -> tuple[ScanStats, CpeDictionaryLookup | None, EmbeddingZeroShotClassifier | None]:
    now = now or utc_now()
    scanner_config = config["scanner"]
    max_attempts = int(config["worker"]["max_attempts"])
    collection = database[collection_name]
    batch_size = int(scanner_config["batch_size"])
    claim_timeout = int(scanner_config["claim_timeout_seconds"])
    taxonomy_version = current_taxonomy_version()
    stats = ScanStats()

    lookup = _reload_lookup_if_needed(lookup, config)
    zero_shot_classifier = reload_zero_shot_if_needed(zero_shot_classifier, config)

    log(
        "scan collection started",
        level="DEBUG",
        collection=collection_name,
        batch_size=batch_size,
        claim_timeout_seconds=claim_timeout,
        taxonomy_version=taxonomy_version,
    )

    cursor = _cursor_with_limit(
        collection.find(build_unclassified_query()),
        batch_size,
    )

    for document in cursor:
        stats.scanned += 1
        document_id = str(document.get("_id") or "")
        if not document_id:
            stats.skipped += 1
            stats.skipped_by_reason["missing_document_id"] = (
                stats.skipped_by_reason.get("missing_document_id", 0) + 1
            )
            continue

        should_process, reason = queue_decision(
            document,
            now=now,
            claim_timeout_seconds=claim_timeout,
            max_attempts=max_attempts,
            taxonomy_version=taxonomy_version,
        )
        if not should_process:
            stats.skipped += 1
            stats.skipped_by_reason[reason] = stats.skipped_by_reason.get(reason, 0) + 1
            log(
                "document skipped",
                level="DEBUG",
                collection=collection_name,
                document_id=document_id,
                reason=reason,
            )
            continue

        try:
            outcome = classify_document(
                collection,
                document,
                config,
                lookup=lookup,
                zero_shot_classifier=zero_shot_classifier,
            )
        except Exception as exc:
            outcome = handle_classification_error(collection, document, exc, config)
            if outcome == "failed":
                stats.failed += 1
                log(
                    "classification failed",
                    level="ERROR",
                    collection=collection_name,
                    document_id=document_id,
                    error=exc,
                )
            else:
                stats.skipped += 1
                stats.skipped_by_reason["retryable_error"] = (
                    stats.skipped_by_reason.get("retryable_error", 0) + 1
                )
                log(
                    "classification error; will retry",
                    level="WARNING",
                    collection=collection_name,
                    document_id=document_id,
                    error=exc,
                )
            continue

        if outcome == "classified":
            stats.classified += 1
        elif outcome == "unclassified":
            stats.unclassified += 1

    log(
        "scan collection completed",
        collection=collection_name,
        scanned=stats.scanned,
        classified=stats.classified,
        unclassified=stats.unclassified,
        failed=stats.failed,
        skipped=stats.skipped_by_reason,
        taxonomy_version=taxonomy_version,
    )
    return stats, lookup, zero_shot_classifier


def scan_once(
    database: Any,
    config: dict[str, Any],
    *,
    lookup: CpeDictionaryLookup | None = None,
    zero_shot_classifier: EmbeddingZeroShotClassifier | None = None,
    now: Any = None,
) -> tuple[ScanStats, CpeDictionaryLookup | None, EmbeddingZeroShotClassifier | None]:
    total = ScanStats()
    for collection_name in config["mongo"]["collections"]:
        stats, lookup, zero_shot_classifier = scan_collection(
            database,
            config,
            collection_name,
            lookup=lookup,
            zero_shot_classifier=zero_shot_classifier,
            now=now,
        )
        total.scanned += stats.scanned
        total.classified += stats.classified
        total.unclassified += stats.unclassified
        total.failed += stats.failed
        total.skipped += stats.skipped
        for reason, count in stats.skipped_by_reason.items():
            total.skipped_by_reason[reason] = total.skipped_by_reason.get(reason, 0) + count
        if stats.classified or stats.unclassified or stats.failed:
            log(
                "collection scan summary",
                collection=collection_name,
                classified=stats.classified,
                unclassified=stats.unclassified,
                failed=stats.failed,
            )
    return total, lookup, zero_shot_classifier


def _request_shutdown(*_: Any) -> None:
    STOP_EVENT.set()


def main() -> None:
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    config = load_config()
    log(
        "configuration loaded",
        database=config["mongo"]["database"],
        collections=",".join(config["mongo"]["collections"]),
        interval_seconds=config["scanner"]["interval_seconds"],
        zero_shot_enabled=bool(config.get("zero_shot", {}).get("enabled")),
    )

    client = create_mongo_client(config)
    database = get_database(client, config)
    lookup = _lookup_from_config(config) if _dictionary_lookup_enabled(config) else None
    zero_shot_classifier = (
        reload_zero_shot_if_needed(None, config)
        if bool(config.get("zero_shot", {}).get("enabled"))
        else None
    )

    try:
        while not STOP_EVENT.is_set():
            try:
                stats, lookup, zero_shot_classifier = scan_once(
                    database,
                    config,
                    lookup=lookup,
                    zero_shot_classifier=zero_shot_classifier,
                )
                log(
                    "scan completed",
                    scanned=stats.scanned,
                    classified=stats.classified,
                    unclassified=stats.unclassified,
                    failed=stats.failed,
                    skipped=stats.skipped,
                )
            except Exception as exc:
                log("scan error", level="ERROR", error=exc)

            interval = int(config["scanner"]["interval_seconds"])
            log("waiting before next scan", level="DEBUG", interval_seconds=interval)
            STOP_EVENT.wait(interval)
    finally:
        client.close()
        log("MongoDB client closed", level="DEBUG")


if __name__ == "__main__":
    main()
