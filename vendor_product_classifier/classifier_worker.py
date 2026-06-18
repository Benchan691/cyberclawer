from __future__ import annotations

import signal
import threading
from typing import Any, Callable

try:
    from .logging_utils import log_event
    from .mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_failed,
        mark_processing,
        mark_queued,
        utc_now_iso,
        write_classification,
    )
    from .rabbitmq_utils import connect, declare_queues, decode_message, publish_json
    from .rule_alias import RuleAliasMatcher, aliases_fingerprint
except ImportError:
    from logging_utils import log_event
    from mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_failed,
        mark_processing,
        mark_queued,
        utc_now_iso,
        write_classification,
    )
    from rabbitmq_utils import connect, declare_queues, decode_message, publish_json
    from rule_alias import RuleAliasMatcher, aliases_fingerprint


STOP_EVENT = threading.Event()
Publisher = Callable[[Any, str, dict[str, Any]], None]
COMPONENT = "vendor-product-worker"


def log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    log_event(COMPONENT, message, level=level, **fields)


def _attempt(task: dict[str, Any]) -> int:
    try:
        return int(task.get("attempt") or 0)
    except (TypeError, ValueError):
        return 0


def _zero_shot_task(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_type": "vendor_product_zero_shot",
        "collection": task["collection"],
        "document_id": task["document_id"],
        "attempt": 0,
        "created_at": utc_now_iso(),
    }


def _retry_task(task: dict[str, Any], attempt: int) -> dict[str, Any]:
    retry = dict(task)
    retry["attempt"] = attempt
    retry["created_at"] = utc_now_iso()
    return retry


def _classification_from_match(match: Any) -> dict[str, Any]:
    return {
        "vendor": match.vendor,
        "product": match.product,
        "confidence": match.confidence,
        "method": match.method,
        "matched_alias": match.matched_alias,
        "matched_text": match.matched_text,
        "status": "classified",
        "classified_at": utc_now_iso(),
    }


def _classification_from_vendor_match(match: Any) -> dict[str, Any]:
    return {
        "vendor": match.vendor,
        "confidence": match.confidence,
        "method": match.method,
        "matched_alias": match.matched_alias,
        "matched_text": match.matched_text,
        "status": "vendor_only",
        "updated_at": utc_now_iso(),
        "reason": "vendor matched but product is not in alias taxonomy",
    }


def _reload_matcher_if_needed(matcher: RuleAliasMatcher) -> RuleAliasMatcher:
    taxonomy_version = aliases_fingerprint()
    if matcher.taxonomy_version == taxonomy_version:
        return matcher
    log(
        "alias taxonomy changed; reloading matcher",
        previous_taxonomy_version=matcher.taxonomy_version,
        taxonomy_version=taxonomy_version,
    )
    return RuleAliasMatcher.from_file()


def process_task(
    database: Any,
    channel: Any,
    task: dict[str, Any],
    matcher: RuleAliasMatcher | None,
    config: dict[str, Any],
    *,
    publish: Publisher = publish_json,
) -> str:
    if task.get("task_type") != "vendor_product_classification":
        raise ValueError(f"Unexpected task_type: {task.get('task_type')}")
    collection_name = str(task["collection"])
    document_id = str(task["document_id"])
    attempt = _attempt(task)
    log(
        "classification task started",
        collection=collection_name,
        document_id=document_id,
        attempt=attempt,
    )
    collection = database[collection_name]
    document = find_document(database, collection_name, document_id)
    if document is None:
        raise ValueError(f"Document not found: {collection_name}/{document_id}")

    if has_vendor_product(document):
        log(
            "classification task skipped",
            collection=collection_name,
            document_id=document_id,
            reason="already_has_vendor_product",
        )
        return "skipped"

    mark_processing(collection, document_id, attempt=attempt, method="rule_alias")
    log(
        "document marked processing",
        level="DEBUG",
        collection=collection_name,
        document_id=document_id,
        method="rule_alias",
        attempt=attempt,
    )

    matcher = matcher or RuleAliasMatcher.from_file()
    match = matcher.match_document(document)
    if match is not None:
        write_classification(collection, document_id, _classification_from_match(match))
        log(
            "rule alias match saved",
            collection=collection_name,
            document_id=document_id,
            vendor=match.vendor,
            product=match.product,
            method=match.method,
            matched_alias=match.matched_alias,
            confidence=match.confidence,
            taxonomy_version=getattr(matcher, "taxonomy_version", None),
        )
        return "classified"

    vendor_match = matcher.match_vendor_document(document)
    if vendor_match is not None:
        write_classification(
            collection,
            document_id,
            _classification_from_vendor_match(vendor_match),
        )
        log(
            "vendor-only alias match saved",
            collection=collection_name,
            document_id=document_id,
            vendor=vendor_match.vendor,
            method=vendor_match.method,
            matched_alias=vendor_match.matched_alias,
            confidence=vendor_match.confidence,
            taxonomy_version=getattr(matcher, "taxonomy_version", None),
        )
        return "vendor_only"

    write_classification(
        collection,
        document_id,
        {
            "status": "pending_zero_shot",
            "method": "rule_alias",
            "updated_at": utc_now_iso(),
        },
    )
    zero_task = _zero_shot_task(task)
    publish(channel, config["queues"]["zero_shot"], zero_task)
    log(
        "no rule match; zero-shot task published",
        collection=collection_name,
        document_id=document_id,
        zero_shot_queue=config["queues"]["zero_shot"],
        zero_shot_created_at=zero_task["created_at"],
    )
    return "pending_zero_shot"


def handle_task_error(
    database: Any,
    channel: Any,
    task: dict[str, Any],
    error: Exception,
    config: dict[str, Any],
    *,
    retry_queue: str,
    publish: Publisher = publish_json,
) -> str:
    collection_name = str(task.get("collection") or "")
    document_id = str(task.get("document_id") or "")
    attempt_count = _attempt(task) + 1
    max_attempts = int(config["worker"]["max_attempts"])

    collection = database[collection_name] if collection_name else None
    if attempt_count >= max_attempts:
        if collection is not None and document_id:
            mark_failed(collection, document_id, error=str(error), attempts=attempt_count)
            log(
                "document marked failed",
                level="ERROR",
                collection=collection_name,
                document_id=document_id,
                attempts=attempt_count,
                error=error,
            )
        publish(
            channel,
            config["queues"]["dead_letter"],
            {
                "task": task,
                "error": str(error),
                "attempts": attempt_count,
                "failed_at": utc_now_iso(),
            },
        )
        log(
            "task published to dead-letter queue",
            level="ERROR",
            collection=collection_name,
            document_id=document_id,
            attempts=attempt_count,
            dead_letter_queue=config["queues"]["dead_letter"],
        )
        return "dead_lettered"

    retry = _retry_task(task, attempt_count)
    publish(channel, retry_queue, retry)
    if collection is not None and document_id:
        mark_queued(collection, document_id, now=retry["created_at"], attempts=attempt_count)
    log(
        "task scheduled for retry",
        level="WARNING",
        collection=collection_name,
        document_id=document_id,
        attempts=attempt_count,
        retry_queue=retry_queue,
        error=error,
    )
    return "retried"


def _request_shutdown(*_: Any) -> None:
    STOP_EVENT.set()


def consume(config: dict[str, Any]) -> None:
    client = create_mongo_client(config)
    database = get_database(client, config)
    matcher = RuleAliasMatcher.from_file()
    log(
        "worker initialized",
        database=config["mongo"]["database"],
        intake_queue=config["queues"]["classification_intake"],
        zero_shot_queue=config["queues"]["zero_shot"],
        dead_letter_queue=config["queues"]["dead_letter"],
        prefetch_count=config["worker"]["prefetch_count"],
        max_attempts=config["worker"]["max_attempts"],
        aliases=len(matcher.candidates),
    )
    try:
        while not STOP_EVENT.is_set():
            connection = None
            try:
                log("connecting to RabbitMQ", level="DEBUG")
                connection = connect(config)
                channel = connection.channel()
                declare_queues(channel, config)
                channel.basic_qos(prefetch_count=int(config["worker"]["prefetch_count"]))
                queue_name = config["queues"]["classification_intake"]
                log("connected", queue=queue_name)
                for method, _, body in channel.consume(queue_name, inactivity_timeout=1):
                    if STOP_EVENT.is_set():
                        break
                    if method is None:
                        continue
                    task: dict[str, Any] = {}
                    try:
                        task = decode_message(body)
                        matcher = _reload_matcher_if_needed(matcher)
                        log(
                            "queue message received",
                            level="DEBUG",
                            collection=task.get("collection"),
                            document_id=task.get("document_id"),
                            attempt=task.get("attempt"),
                            delivery_tag=method.delivery_tag,
                        )
                        result = process_task(database, channel, task, matcher, config)
                        log(
                            "processed task",
                            result=result,
                            collection=task.get("collection"),
                            document_id=task.get("document_id"),
                        )
                    except Exception as exc:
                        result = handle_task_error(
                            database,
                            channel,
                            task,
                            exc,
                            config,
                            retry_queue=queue_name,
                        )
                        log("task error handled", level="ERROR", result=result, error=exc)
                    channel.basic_ack(method.delivery_tag)
                    log("queue message acked", level="DEBUG", delivery_tag=method.delivery_tag)
            except Exception as exc:
                log("reconnecting after error", level="ERROR", error=exc)
                STOP_EVENT.wait(5)
            finally:
                if connection is not None and getattr(connection, "is_open", False):
                    connection.close()
                    log("RabbitMQ connection closed", level="DEBUG")
    finally:
        client.close()
        log("MongoDB client closed", level="DEBUG")


def main() -> None:
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    consume(load_config())


if __name__ == "__main__":
    main()
