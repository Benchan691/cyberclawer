from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from typing import Any, Callable

try:
    from .classifier_worker import handle_task_error
    from .logging_utils import log_event
    from .mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_processing,
        utc_now_iso,
        write_classification,
    )
    from .rabbitmq_utils import connect, declare_queues, decode_message, publish_json
    from .rule_alias import aliases_fingerprint, evidence_texts, load_aliases
except ImportError:
    from classifier_worker import handle_task_error
    from logging_utils import log_event
    from mongo_utils import (
        create_mongo_client,
        find_document,
        get_database,
        has_vendor_product,
        load_config,
        mark_processing,
        utc_now_iso,
        write_classification,
    )
    from rabbitmq_utils import connect, declare_queues, decode_message, publish_json
    from rule_alias import aliases_fingerprint, evidence_texts, load_aliases


STOP_EVENT = threading.Event()
Publisher = Callable[[Any, str, dict[str, Any]], None]
COMPONENT = "vendor-product-zero-shot"


@dataclass(frozen=True)
class TaxonomyLabel:
    vendor: str
    product: str
    alias: str
    text: str


def log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    log_event(COMPONENT, message, level=level, **fields)


def _attempt(task: dict[str, Any]) -> int:
    try:
        return int(task.get("attempt") or 0)
    except (TypeError, ValueError):
        return 0


def _vector(value: Any) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    return [float(item) for item in value]


def cosine_similarity(left: Any, right: Any) -> float:
    a = _vector(left)
    b = _vector(right)
    if len(a) != len(b) or not a:
        raise ValueError("Embedding vectors must have the same non-zero length")
    dot = sum(x * y for x, y in zip(a, b))
    left_norm = sum(x * x for x in a) ** 0.5
    right_norm = sum(y * y for y in b) ** 0.5
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def taxonomy_labels(aliases: list[dict[str, Any]]) -> list[TaxonomyLabel]:
    labels: list[TaxonomyLabel] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in aliases:
        vendor = str(entry.get("vendor") or "").strip()
        product = str(entry.get("product") or "").strip()
        if not vendor or not product:
            continue
        names = [f"{vendor} {product}", *list(entry.get("aliases") or [])]
        for alias in names:
            alias_text = str(alias or "").strip()
            if not alias_text:
                continue
            key = (vendor, product, alias_text.casefold())
            if key in seen:
                continue
            seen.add(key)
            labels.append(
                TaxonomyLabel(
                    vendor=vendor,
                    product=product,
                    alias=alias_text,
                    text=f"{vendor} {product}: {alias_text}",
                )
            )
    return labels


class EmbeddingZeroShotClassifier:
    def __init__(
        self,
        *,
        model_name: str,
        confidence_threshold: float,
        aliases: list[dict[str, Any]] | None = None,
        model: Any = None,
    ) -> None:
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.aliases = aliases if aliases is not None else load_aliases()
        self.taxonomy_version = aliases_fingerprint(self.aliases)
        self.labels = taxonomy_labels(self.aliases)
        self.model = model
        self._label_embeddings: list[Any] | None = None
        log(
            "zero-shot classifier initialized",
            model_name=self.model_name,
            confidence_threshold=self.confidence_threshold,
            taxonomy_version=self.taxonomy_version,
            taxonomy_entries=len(self.aliases),
            labels=len(self.labels),
            lazy_model_load=self.model is None,
        )

    def _load_model(self) -> Any:
        if self.model is None:
            log("loading sentence-transformers model", model_name=self.model_name)
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer(self.model_name)
            log("sentence-transformers model loaded", model_name=self.model_name)
        return self.model

    def _encode(self, texts: list[str]) -> list[Any]:
        model = self._load_model()
        try:
            embeddings = model.encode(texts, normalize_embeddings=True)
        except TypeError:
            embeddings = model.encode(texts)
        if hasattr(embeddings, "tolist"):
            embeddings = embeddings.tolist()
        return list(embeddings)

    def _ensure_label_embeddings(self) -> list[Any]:
        if self._label_embeddings is None:
            log("embedding taxonomy labels", level="DEBUG", labels=len(self.labels))
            self._label_embeddings = self._encode([label.text for label in self.labels])
            log("taxonomy label embeddings ready", labels=len(self._label_embeddings))
        return self._label_embeddings

    def classify(self, document: dict[str, Any]) -> dict[str, Any]:
        texts = evidence_texts(document)
        evidence = "\n".join(texts)[:12000]
        log(
            "zero-shot evidence prepared",
            level="DEBUG",
            document_id=document.get("_id"),
            evidence_fields=len(texts),
            evidence_chars=len(evidence),
        )
        if not evidence:
            log(
                "zero-shot skipped because document has no evidence text",
                level="WARNING",
                document_id=document.get("_id"),
            )
            return {
                "classified": False,
                "confidence": 0.0,
                "reason": "no evidence text",
            }
        if not self.labels:
            log(
                "zero-shot skipped because alias taxonomy is empty",
                level="ERROR",
                document_id=document.get("_id"),
            )
            return {
                "classified": False,
                "confidence": 0.0,
                "reason": "empty alias taxonomy",
            }

        document_embedding = self._encode([evidence])[0]
        label_embeddings = self._ensure_label_embeddings()
        best_index = 0
        best_score = -1.0
        for index, label_embedding in enumerate(label_embeddings):
            score = cosine_similarity(document_embedding, label_embedding)
            if score > best_score:
                best_score = score
                best_index = index

        best = self.labels[best_index]
        classified = best_score >= self.confidence_threshold
        log(
            "zero-shot best candidate selected",
            document_id=document.get("_id"),
            vendor=best.vendor,
            product=best.product,
            matched_alias=best.alias,
            confidence=float(best_score),
            threshold=self.confidence_threshold,
            classified=classified,
        )
        result = {
            "classified": classified,
            "vendor": best.vendor,
            "product": best.product,
            "confidence": float(best_score),
            "matched_alias": best.alias,
            "matched_text": evidence[:2000],
        }
        if not result["classified"]:
            result["reason"] = "confidence below threshold"
        return result


def _classifier_from_config(config: dict[str, Any]) -> EmbeddingZeroShotClassifier:
    zero_shot = config["zero_shot"]
    return EmbeddingZeroShotClassifier(
        model_name=zero_shot["model_name"],
        confidence_threshold=float(zero_shot["confidence_threshold"]),
    )


def _reload_classifier_if_needed(
    classifier: EmbeddingZeroShotClassifier | None,
    config: dict[str, Any],
) -> EmbeddingZeroShotClassifier | None:
    if classifier is None:
        return _classifier_from_config(config) if config["zero_shot"].get("enabled") else None
    taxonomy_version = aliases_fingerprint()
    if classifier.taxonomy_version == taxonomy_version:
        return classifier
    log(
        "alias taxonomy changed; reloading zero-shot labels",
        previous_taxonomy_version=classifier.taxonomy_version,
        taxonomy_version=taxonomy_version,
    )
    return _classifier_from_config(config)


def _disabled_classification() -> dict[str, Any]:
    return {
        "status": "unclassified",
        "method": "rule_alias",
        "reason": "no rule alias match and zero-shot disabled",
        "updated_at": utc_now_iso(),
    }


def _success_classification(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "vendor": result["vendor"],
        "product": result["product"],
        "confidence": float(result["confidence"]),
        "method": "zero_shot_embedding",
        "matched_alias": result.get("matched_alias"),
        "matched_text": result.get("matched_text"),
        "status": "classified",
        "classified_at": utc_now_iso(),
    }


def _low_confidence_classification(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "unclassified",
        "method": "zero_shot_embedding",
        "reason": result.get("reason") or "confidence below threshold",
        "confidence": float(result.get("confidence") or 0.0),
        "best_vendor": result.get("vendor"),
        "best_product": result.get("product"),
        "matched_alias": result.get("matched_alias"),
        "matched_text": result.get("matched_text"),
        "updated_at": utc_now_iso(),
    }


def process_task(
    database: Any,
    channel: Any,
    task: dict[str, Any],
    classifier: Any,
    config: dict[str, Any],
    *,
    publish: Publisher = publish_json,
) -> str:
    if task.get("task_type") != "vendor_product_zero_shot":
        raise ValueError(f"Unexpected task_type: {task.get('task_type')}")
    collection_name = str(task["collection"])
    document_id = str(task["document_id"])
    attempt = _attempt(task)
    log(
        "zero-shot task started",
        collection=collection_name,
        document_id=document_id,
        attempt=attempt,
        enabled=bool(config["zero_shot"].get("enabled")),
    )
    collection = database[collection_name]
    document = find_document(database, collection_name, document_id)
    if document is None:
        raise ValueError(f"Document not found: {collection_name}/{document_id}")
    if has_vendor_product(document):
        log(
            "zero-shot task skipped",
            collection=collection_name,
            document_id=document_id,
            reason="already_has_vendor_product",
        )
        return "skipped"

    if not bool(config["zero_shot"].get("enabled")):
        write_classification(collection, document_id, _disabled_classification())
        log(
            "zero-shot disabled; document marked unclassified",
            collection=collection_name,
            document_id=document_id,
        )
        return "unclassified"

    mark_processing(
        collection,
        document_id,
        attempt=attempt,
        method="zero_shot_embedding",
    )
    log(
        "document marked processing",
        level="DEBUG",
        collection=collection_name,
        document_id=document_id,
        method="zero_shot_embedding",
        attempt=attempt,
    )
    classifier = classifier or _classifier_from_config(config)
    result = classifier.classify(document)
    if result.get("classified"):
        write_classification(collection, document_id, _success_classification(result))
        log(
            "zero-shot classification saved",
            collection=collection_name,
            document_id=document_id,
            vendor=result.get("vendor"),
            product=result.get("product"),
            confidence=result.get("confidence"),
            matched_alias=result.get("matched_alias"),
        )
        return "classified"

    write_classification(collection, document_id, _low_confidence_classification(result))
    log(
        "zero-shot low-confidence result saved",
        level="WARNING",
        collection=collection_name,
        document_id=document_id,
        best_vendor=result.get("vendor"),
        best_product=result.get("product"),
        confidence=result.get("confidence"),
        reason=result.get("reason"),
    )
    return "unclassified"


def _request_shutdown(*_: Any) -> None:
    STOP_EVENT.set()


def consume(config: dict[str, Any]) -> None:
    client = create_mongo_client(config)
    database = get_database(client, config)
    classifier = _classifier_from_config(config) if config["zero_shot"].get("enabled") else None
    log(
        "zero-shot worker initialized",
        database=config["mongo"]["database"],
        zero_shot_queue=config["queues"]["zero_shot"],
        dead_letter_queue=config["queues"]["dead_letter"],
        prefetch_count=config["worker"]["prefetch_count"],
        max_attempts=config["worker"]["max_attempts"],
        enabled=bool(config["zero_shot"].get("enabled")),
        model_name=config["zero_shot"].get("model_name"),
        confidence_threshold=config["zero_shot"].get("confidence_threshold"),
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
                queue_name = config["queues"]["zero_shot"]
                log("connected", queue=queue_name)
                for method, _, body in channel.consume(queue_name, inactivity_timeout=1):
                    if STOP_EVENT.is_set():
                        break
                    if method is None:
                        continue
                    task: dict[str, Any] = {}
                    try:
                        task = decode_message(body)
                        classifier = _reload_classifier_if_needed(classifier, config)
                        log(
                            "queue message received",
                            level="DEBUG",
                            collection=task.get("collection"),
                            document_id=task.get("document_id"),
                            attempt=task.get("attempt"),
                            delivery_tag=method.delivery_tag,
                        )
                        result = process_task(database, channel, task, classifier, config)
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
