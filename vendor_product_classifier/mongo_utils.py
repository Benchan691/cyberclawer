from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymongo import MongoClient

try:
    from . import CLASSIFIER_VERSION
except ImportError:
    CLASSIFIER_VERSION = 2


ACTIVE_STATUSES = {"queued", "processing", "classified"}
REQUEUE_STATUSES = {"unclassified", "failed"}


def classifier_dir() -> Path:
    return Path(__file__).resolve().parent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def current_taxonomy_version() -> str:
    try:
        from .cpe_dictionary import cpe_fingerprint
    except ImportError:
        from cpe_dictionary import cpe_fingerprint

    config = load_config(require_secrets=False)
    path = (config.get("cpe_dictionary") or {}).get("path")
    return cpe_fingerprint(path)


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        key, separator, value = line.partition("=")
        if not separator or not key.strip() or key.strip() in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key.strip()] = value


def load_config(base_dir: str | Path | None = None, *, require_secrets: bool = True) -> dict[str, Any]:
    base = Path(base_dir) if base_dir is not None else classifier_dir()
    load_dotenv(base / ".env")

    config_path = Path(os.getenv("CLASSIFIER_CONFIG", "config/classifier.json"))
    if not config_path.is_absolute():
        config_path = base / config_path
    with config_path.open(encoding="utf-8") as handle:
        config = json.load(handle)

    config["ATLAS_MONGO_URI"] = os.getenv("ATLAS_MONGO_URI", "")
    config["RABBITMQ_URL"] = os.getenv("RABBITMQ_URL", "")

    if require_secrets:
        missing = [
            name
            for name in ("ATLAS_MONGO_URI", "RABBITMQ_URL")
            if not config.get(name)
        ]
        if missing:
            raise ValueError(
                "Missing required environment variable(s): " + ", ".join(missing)
            )
    return config


def create_mongo_client(config: dict[str, Any]) -> MongoClient:
    return MongoClient(config["ATLAS_MONGO_URI"], serverSelectionTimeoutMS=5000)


def get_database(client: MongoClient, config: dict[str, Any]) -> Any:
    return client[config["mongo"]["database"]]


def classification_status(document: dict[str, Any]) -> str | None:
    classification = document.get("classification")
    if not isinstance(classification, dict):
        return None
    status = classification.get("status")
    return str(status) if status is not None else None


def has_vendor_product(document: dict[str, Any]) -> bool:
    classification = document.get("classification")
    if not isinstance(classification, dict):
        return False
    return bool(classification.get("vendor")) and bool(classification.get("product"))


def build_unclassified_query() -> dict[str, Any]:
    return {
        "$or": [
            {"classification": {"$exists": False}},
            {"classification.vendor": {"$exists": False}},
            {"classification.product": {"$exists": False}},
            {"classification.status": {"$in": ["unclassified", "failed"]}},
            {"classification.status": {"$exists": False}},
        ]
    }


def _claim_timestamp(document: dict[str, Any]) -> datetime | None:
    classification = document.get("classification")
    if not isinstance(classification, dict):
        return None
    for field in ("processing_started_at", "queued_at", "updated_at"):
        parsed = parse_datetime(classification.get(field))
        if parsed is not None:
            return parsed
    return None


def is_stale_claim(
    document: dict[str, Any],
    *,
    now: datetime,
    claim_timeout_seconds: int,
) -> bool:
    status = classification_status(document)
    if status not in {"queued", "processing"}:
        return False
    timestamp = _claim_timestamp(document)
    if timestamp is None:
        return True
    age_seconds = (now - timestamp).total_seconds()
    return age_seconds >= claim_timeout_seconds


def should_queue_document(
    document: dict[str, Any],
    *,
    now: datetime,
    claim_timeout_seconds: int,
    max_attempts: int,
    taxonomy_version: str | None = None,
) -> bool:
    return queue_decision(
        document,
        now=now,
        claim_timeout_seconds=claim_timeout_seconds,
        max_attempts=max_attempts,
        taxonomy_version=taxonomy_version,
    )[0]


def queue_decision(
    document: dict[str, Any],
    *,
    now: datetime,
    claim_timeout_seconds: int,
    max_attempts: int,
    taxonomy_version: str | None = None,
) -> tuple[bool, str]:
    taxonomy_version = taxonomy_version or current_taxonomy_version()
    if has_vendor_product(document):
        return False, "has_vendor_product"

    status = classification_status(document)
    if status == "classified":
        return False, status
    if status in {"queued", "processing"}:
        stale = is_stale_claim(
            document,
            now=now,
            claim_timeout_seconds=claim_timeout_seconds,
        )
        return stale, "stale_claim" if stale else f"active_{status}"
    if status == "failed":
        classification = document.get("classification") or {}
        attempts = int(classification.get("attempts") or 0)
        if attempts < max_attempts:
            return True, "failed_retryable"
        return False, "failed_max_attempts"
    if status is None:
        return True, "missing_status"
    if status == "unclassified":
        classification = document.get("classification") or {}
        previous_taxonomy = classification.get("dictionary_version") or classification.get("taxonomy_version")
        if previous_taxonomy == taxonomy_version:
            return False, "unclassified_current_dictionary"
        if previous_taxonomy:
            return True, "dictionary_updated"
        return True, "missing_dictionary_version"
    if status in REQUEUE_STATUSES:
        return True, status
    return False, f"unsupported_status:{status}"


def find_document(database: Any, collection_name: str, document_id: str) -> dict[str, Any] | None:
    return database[collection_name].find_one({"_id": document_id})


def write_classification(collection: Any, document_id: str, classification: dict[str, Any]) -> Any:
    payload = dict(classification)
    payload.setdefault("classifier_version", CLASSIFIER_VERSION)
    if payload.get("status") in {"classified", "unclassified"}:
        payload.setdefault("dictionary_version", current_taxonomy_version())
    return collection.update_one(
        {"_id": document_id},
        {"$set": {"classification": payload}},
    )


def mark_queued(collection: Any, document_id: str, *, now: str | None = None, attempts: int | None = None) -> Any:
    classification: dict[str, Any] = {
        "status": "queued",
        "queued_at": now or utc_now_iso(),
        "classifier_version": CLASSIFIER_VERSION,
    }
    if attempts is not None:
        classification["attempts"] = attempts
    return write_classification(collection, document_id, classification)


def mark_processing(collection: Any, document_id: str, *, attempt: int, method: str | None = None) -> Any:
    classification: dict[str, Any] = {
        "status": "processing",
        "attempts": attempt,
        "processing_started_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "classifier_version": CLASSIFIER_VERSION,
    }
    if method:
        classification["method"] = method
    return write_classification(collection, document_id, classification)


def mark_failed(collection: Any, document_id: str, *, error: str, attempts: int) -> Any:
    return write_classification(
        collection,
        document_id,
        {
            "status": "failed",
            "error": error,
            "attempts": attempts,
            "updated_at": utc_now_iso(),
            "classifier_version": CLASSIFIER_VERSION,
        },
    )
