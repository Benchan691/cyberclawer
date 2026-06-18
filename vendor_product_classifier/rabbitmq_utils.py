from __future__ import annotations

import json
from typing import Any

try:
    from .logging_utils import log_event
except ImportError:
    from logging_utils import log_event

try:
    import pika
except ImportError:  # pragma: no cover - runtime dependency in classifier image.
    pika = None

COMPONENT = "vendor-product-rabbitmq"


def _require_pika() -> Any:
    if pika is None:
        raise RuntimeError("pika is required for RabbitMQ execution")
    return pika


def connect(config: dict[str, Any]) -> Any:
    pika_module = _require_pika()
    log_event(
        COMPONENT,
        "opening RabbitMQ connection",
        level="DEBUG",
        rabbitmq_url=config["RABBITMQ_URL"],
    )
    return pika_module.BlockingConnection(
        pika_module.URLParameters(config["RABBITMQ_URL"])
    )


def queue_names(config: dict[str, Any]) -> dict[str, str]:
    return {
        "classification_intake": config["queues"]["classification_intake"],
        "zero_shot": config["queues"]["zero_shot"],
        "dead_letter": config["queues"]["dead_letter"],
    }


def _dead_letter_arguments(dead_letter_queue: str) -> dict[str, str]:
    return {
        "x-dead-letter-exchange": "",
        "x-dead-letter-routing-key": dead_letter_queue,
    }


def declare_queues(channel: Any, config: dict[str, Any]) -> None:
    names = queue_names(config)
    channel.queue_declare(queue=names["dead_letter"], durable=True)
    log_event(
        COMPONENT,
        "queue declared",
        level="DEBUG",
        queue=names["dead_letter"],
        durable=True,
    )
    for name in (names["classification_intake"], names["zero_shot"]):
        channel.queue_declare(
            queue=name,
            durable=True,
            arguments=_dead_letter_arguments(names["dead_letter"]),
        )
        log_event(
            COMPONENT,
            "queue declared",
            level="DEBUG",
            queue=name,
            durable=True,
            dead_letter_queue=names["dead_letter"],
        )


def basic_properties() -> Any:
    if pika is None:
        return None
    return pika.BasicProperties(
        delivery_mode=2,
        content_type="application/json",
    )


def publish_json(channel: Any, queue_name: str, message: dict[str, Any]) -> None:
    body = json.dumps(message, ensure_ascii=False, default=str).encode("utf-8")
    channel.basic_publish(
        exchange="",
        routing_key=queue_name,
        body=body,
        properties=basic_properties(),
    )
    log_event(
        COMPONENT,
        "message published",
        level="DEBUG",
        queue=queue_name,
        task_type=message.get("task_type"),
        collection=message.get("collection"),
        document_id=message.get("document_id"),
        attempt=message.get("attempt"),
    )


def decode_message(body: bytes | str) -> dict[str, Any]:
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError("RabbitMQ message payload must be a JSON object")
    return payload
