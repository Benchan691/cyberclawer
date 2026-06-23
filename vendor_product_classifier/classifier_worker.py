from __future__ import annotations

import signal
import threading
from typing import Any, Callable

try:
    from .cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from .cve_cpe import extract_vendor_product_evidence
    from .logging_utils import log_event
    from .mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_failed,
        mark_queued,
        utc_now_iso,
        write_classification,
    )
    from .rabbitmq_utils import connect, declare_queues, decode_message, publish_json
except ImportError:
    from cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from cve_cpe import extract_vendor_product_evidence
    from logging_utils import log_event
    from mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_failed,
        mark_queued,
        utc_now_iso,
        write_classification,
    )
    from rabbitmq_utils import connect, declare_queues, decode_message, publish_json


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


def _dictionary_path(config: dict[str, Any]) -> str | None:
    value = (config.get("cpe_dictionary") or {}).get("path")
    return str(value) if value else None


def _lookup_from_config(config: dict[str, Any]) -> CpeDictionaryLookup:
    return CpeDictionaryLookup(dictionary_path=_dictionary_path(config))


def _reload_lookup_if_needed(
    lookup: CpeDictionaryLookup | None,
    config: dict[str, Any],
) -> CpeDictionaryLookup:
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


def _dictionary_lookup_enabled(config: dict[str, Any]) -> bool:
    return bool((config.get("dictionary_lookup") or {}).get("enabled", True))


def _zero_shot_task(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_type": "vendor_product_zero_shot",
        "collection": task["collection"],
        "document_id": task["document_id"],
        "attempt": _attempt(task),
        "created_at": utc_now_iso(),
    }


def _retry_task(task: dict[str, Any], attempt: int) -> dict[str, Any]:
    retry = dict(task)
    retry["attempt"] = attempt
    retry["created_at"] = utc_now_iso()
    return retry


def process_task(
    database: Any,
    channel: Any,
    task: dict[str, Any],
    matcher: Any,
    config: dict[str, Any],
    *,
    lookup: CpeDictionaryLookup | None = None,
    publish: Publisher = publish_json,
) -> str:
    if task.get("task_type") != "vendor_product_classification":
        raise ValueError(f"Unexpected task_type: {task.get('task_type')}")
    collection_name = str(task["collection"])
    document_id = str(task["document_id"])
    if collection_name != "cve":
        return "skipped_non_cve"

    document = find_document(database, collection_name, document_id)
    if document is None:
        raise ValueError(f"Document not found: {collection_name}/{document_id}")
    if has_vendor_product(document):
        return "skipped"

    if _dictionary_lookup_enabled(config):
        lookup = lookup or _lookup_from_config(config)
        hit = lookup.lookup(extract_vendor_product_evidence(document))
        if hit is not None:
            collection = database[collection_name]
            write_classification(
                collection,
                document_id,
                {
                    "status": "classified",
                    "vendor": hit.candidate.vendor,
                    "product": hit.candidate.product,
                    "cpe": hit.candidate.cpe,
                    "confidence": hit.confidence,
                    "method": "dictionary",
                    "dictionary_version": lookup.dictionary_version,
                    "updated_at": utc_now_iso(),
                },
            )
            log(
                "dictionary classification written",
                collection=collection_name,
                document_id=document_id,
                match_type=hit.match_type,
                evidence=hit.evidence,
            )
            return "classified"

    zero_task = _zero_shot_task(task)
    publish(channel, config["queues"]["zero_shot"], zero_task)
    log(
        "zero-shot task published",
        collection=collection_name,
        document_id=document_id,
        zero_shot_queue=config["queues"]["zero_shot"],
    )
    return "queued_zero_shot"


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
        return "dead_lettered"

    retry = _retry_task(task, attempt_count)
    publish(channel, retry_queue, retry)
    if collection is not None and document_id:
        mark_queued(collection, document_id, now=retry["created_at"], attempts=attempt_count)
    return "retried"


def _request_shutdown(*_: Any) -> None:
    STOP_EVENT.set()


def consume(config: dict[str, Any]) -> None:
    client = create_mongo_client(config)
    database = get_database(client, config)
    lookup = _lookup_from_config(config) if _dictionary_lookup_enabled(config) else None
    try:
        while not STOP_EVENT.is_set():
            connection = None
            try:
                connection = connect(config)
                channel = connection.channel()
                declare_queues(channel, config)
                channel.basic_qos(prefetch_count=int(config["worker"]["prefetch_count"]))
                queue_name = config["queues"]["classification_intake"]
                for method, _, body in channel.consume(queue_name, inactivity_timeout=1):
                    if STOP_EVENT.is_set():
                        break
                    if method is None:
                        continue
                    task: dict[str, Any] = {}
                    try:
                        task = decode_message(body)
                        lookup = _reload_lookup_if_needed(lookup, config)
                        process_task(database, channel, task, None, config, lookup=lookup)
                    except Exception as exc:
                        handle_task_error(
                            database,
                            channel,
                            task,
                            exc,
                            config,
                            retry_queue=queue_name,
                        )
                    channel.basic_ack(method.delivery_tag)
            except Exception as exc:
                log("reconnecting after error", level="ERROR", error=exc)
                STOP_EVENT.wait(5)
            finally:
                if connection is not None and getattr(connection, "is_open", False):
                    connection.close()
    finally:
        client.close()


def main() -> None:
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    consume(load_config())


if __name__ == "__main__":
    main()
