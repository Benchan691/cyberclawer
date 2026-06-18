from __future__ import annotations

import signal
import threading
from typing import Any, Callable

try:
    from .logging_utils import log_event
    from .mongo_utils import (
        build_unclassified_query,
        create_mongo_client,
        current_taxonomy_version,
        get_database,
        load_config,
        mark_queued,
        queue_decision,
        utc_now,
        utc_now_iso,
    )
    from .rabbitmq_utils import connect, declare_queues, publish_json
except ImportError:
    from logging_utils import log_event
    from mongo_utils import (
        build_unclassified_query,
        create_mongo_client,
        current_taxonomy_version,
        get_database,
        load_config,
        mark_queued,
        queue_decision,
        utc_now,
        utc_now_iso,
    )
    from rabbitmq_utils import connect, declare_queues, publish_json


STOP_EVENT = threading.Event()
Publisher = Callable[[Any, str, dict[str, Any]], None]
COMPONENT = "vendor-product-scanner"


def log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    log_event(COMPONENT, message, level=level, **fields)


def build_task(collection_name: str, document_id: str, *, attempt: int = 0) -> dict[str, Any]:
    return {
        "task_type": "vendor_product_classification",
        "collection": collection_name,
        "document_id": document_id,
        "attempt": attempt,
        "created_at": utc_now_iso(),
    }


def _cursor_with_limit(cursor: Any, batch_size: int) -> Any:
    limit = getattr(cursor, "limit", None)
    if limit is not None:
        return limit(batch_size)
    return cursor


def scan_collection(
    database: Any,
    channel: Any,
    config: dict[str, Any],
    collection_name: str,
    *,
    publish: Publisher = publish_json,
    now: Any = None,
) -> int:
    now = now or utc_now()
    scanner_config = config["scanner"]
    max_attempts = int(config["worker"]["max_attempts"])
    queue_name = config["queues"]["classification_intake"]
    collection = database[collection_name]
    batch_size = int(scanner_config["batch_size"])
    claim_timeout = int(scanner_config["claim_timeout_seconds"])
    taxonomy_version = current_taxonomy_version()
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

    queued = 0
    scanned = 0
    skipped_by_reason: dict[str, int] = {}
    for document in cursor:
        scanned += 1
        document_id = str(document.get("_id") or "")
        if not document_id:
            skipped_by_reason["missing_document_id"] = (
                skipped_by_reason.get("missing_document_id", 0) + 1
            )
            continue
        should_queue, reason = queue_decision(
            document,
            now=now,
            claim_timeout_seconds=claim_timeout,
            max_attempts=max_attempts,
            taxonomy_version=taxonomy_version,
        )
        if not should_queue:
            skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
            log(
                "document skipped",
                level="DEBUG",
                collection=collection_name,
                document_id=document_id,
                reason=reason,
            )
            continue
        task = build_task(collection_name, document_id)
        log(
            "publishing classification task",
            level="DEBUG",
            collection=collection_name,
            document_id=document_id,
            queue=queue_name,
            attempt=task["attempt"],
            taxonomy_version=taxonomy_version,
        )
        publish(channel, queue_name, task)
        mark_queued(collection, document_id, now=task["created_at"])
        log(
            "document marked queued",
            level="DEBUG",
            collection=collection_name,
            document_id=document_id,
            queued_at=task["created_at"],
        )
        queued += 1
    log(
        "scan collection completed",
        collection=collection_name,
        scanned=scanned,
        queued=queued,
        skipped=skipped_by_reason,
        taxonomy_version=taxonomy_version,
    )
    return queued


def scan_once(
    database: Any,
    channel: Any,
    config: dict[str, Any],
    *,
    publish: Publisher = publish_json,
    now: Any = None,
) -> int:
    total = 0
    for collection_name in config["mongo"]["collections"]:
        queued = scan_collection(
            database,
            channel,
            config,
            collection_name,
            publish=publish,
            now=now,
        )
        if queued:
            log("queued documents", collection=collection_name, count=queued)
        total += queued
    return total


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
        intake_queue=config["queues"]["classification_intake"],
        zero_shot_queue=config["queues"]["zero_shot"],
        dead_letter_queue=config["queues"]["dead_letter"],
        interval_seconds=config["scanner"]["interval_seconds"],
    )
    client = create_mongo_client(config)
    database = get_database(client, config)
    try:
        while not STOP_EVENT.is_set():
            connection = None
            try:
                log("connecting to RabbitMQ", level="DEBUG")
                connection = connect(config)
                channel = connection.channel()
                declare_queues(channel, config)
                log("RabbitMQ connected and queues declared")
                queued = scan_once(database, channel, config)
                log("scan completed", queued=queued)
            except Exception as exc:
                log("scan error", level="ERROR", error=exc)
            finally:
                if connection is not None and getattr(connection, "is_open", False):
                    connection.close()
                    log("RabbitMQ connection closed", level="DEBUG")

            interval = int(config["scanner"]["interval_seconds"])
            log("waiting before next scan", level="DEBUG", interval_seconds=interval)
            STOP_EVENT.wait(interval)
    finally:
        client.close()
        log("MongoDB client closed", level="DEBUG")


if __name__ == "__main__":
    main()
