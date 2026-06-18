from __future__ import annotations

import importlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .mongo import redact_mongo_uri

from .mongo_filter_defaults import (
    CATEGORICAL_FIELDS as CATEGORICAL_BASE_FIELDS,
    DYNAMIC_ATTACK_METRICS_PATH,
    TEXT_FIELDS,
)


SORT_SPEC: tuple[tuple[str, int], ...] = (
    ("updated_time", -1),
    ("disclosure_date", -1),
    ("type", 1),
    ("code", -1),
)


@dataclass
class MongoFilterState:
    selected_values: dict[str, set[str]] = field(default_factory=dict)
    text_filters: dict[str, str] = field(default_factory=dict)
    page: int = 0
    page_size: int = 10

    def toggle_value(self, field_name: str, value: str) -> None:
        values = self.selected_values.setdefault(field_name, set())
        if value in values:
            values.remove(value)
            if not values:
                self.selected_values.pop(field_name, None)
        else:
            values.add(value)
        self.page = 0

    def set_text_filter(self, field_name: str, value: str) -> None:
        value = value.strip()
        if value:
            self.text_filters[field_name] = value
        else:
            self.text_filters.pop(field_name, None)
        self.page = 0

    def clear_field(self, field_name: str) -> None:
        self.selected_values.pop(field_name, None)
        self.text_filters.pop(field_name, None)
        self.page = 0

    def build_query(self) -> dict[str, Any]:
        return build_mongo_query(self.selected_values, self.text_filters)

    def filters_payload(self) -> dict[str, Any]:
        return {
            "checkboxes": {
                field_name: sorted(values)
                for field_name, values in sorted(self.selected_values.items())
                if values
            },
            "text": {
                field_name: value
                for field_name, value in sorted(self.text_filters.items())
                if value
            },
        }


def build_mongo_query(
    selected_values: dict[str, set[str]],
    text_filters: dict[str, str],
) -> dict[str, Any]:
    clauses: list[dict[str, Any]] = []

    for field_name, values in sorted(selected_values.items()):
        cleaned = sorted(str(value) for value in values if str(value))
        if not cleaned:
            continue
        if len(cleaned) == 1:
            clauses.append({field_name: cleaned[0]})
        else:
            clauses.append({field_name: {"$in": cleaned}})

    for field_name, value in sorted(text_filters.items()):
        value = value.strip()
        if value:
            clauses.append({field_name: {"$regex": re.escape(value), "$options": "i"}})

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}


def filter_fields_for_provider(provider_key: str) -> tuple[tuple[str, ...], tuple[str, ...], str | None]:
    try:
        module = importlib.import_module(f"vuln_scraper.scrapers.{provider_key}.filter_fields")
    except ModuleNotFoundError:
        return CATEGORICAL_BASE_FIELDS, TEXT_FIELDS, DYNAMIC_ATTACK_METRICS_PATH

    categorical_fields = _dedupe_fields(
        (*CATEGORICAL_BASE_FIELDS, *tuple(getattr(module, "CATEGORICAL_FIELDS", ())))
    )
    text_fields = tuple(getattr(module, "TEXT_FIELDS", TEXT_FIELDS))
    dynamic_path = getattr(module, "DYNAMIC_ATTACK_METRICS_PATH", None)
    return categorical_fields, text_fields, dynamic_path


def _dedupe_fields(fields: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if field in seen:
            continue
        result.append(field)
        seen.add(field)
    return tuple(result)


def available_categorical_fields(
    collection: Any,
    *,
    base_fields: tuple[str, ...] = CATEGORICAL_BASE_FIELDS,
    dynamic_object_path: str | None = DYNAMIC_ATTACK_METRICS_PATH,
    sample_size: int = 500,
) -> tuple[str, ...]:
    dynamic_fields = set()
    if dynamic_object_path:
        dynamic_fields = {
            f"{dynamic_object_path}.{key}"
            for key in _discover_object_keys(collection, dynamic_object_path, sample_size=sample_size)
        }
    return tuple(sorted((*base_fields, *dynamic_fields)))


def distinct_values(collection: Any, field_name: str, *, limit: int = 200) -> list[str]:
    values = collection.distinct(field_name)
    unique = {
        str(value)
        for value in _flatten(values)
        if value is not None and str(value).strip()
    }
    return sorted(unique, key=lambda value: value.casefold())[:limit]


def fetch_filtered_records(
    collection: Any,
    state: MongoFilterState,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    query = state.build_query()
    cursor = collection.find(query).sort(list(SORT_SPEC))
    if limit is not None:
        cursor = cursor.limit(limit)
    return [strip_mongo_id(item) for item in cursor]


def fetch_filtered_page(
    collection: Any,
    state: MongoFilterState,
) -> tuple[int, list[dict[str, Any]]]:
    query = state.build_query()
    total = collection.count_documents(query)
    cursor = (
        collection.find(query)
        .sort(list(SORT_SPEC))
        .skip(state.page * state.page_size)
        .limit(state.page_size)
    )
    return total, [strip_mongo_id(item) for item in cursor]


def export_filtered_results(
    collection: Any,
    state: MongoFilterState,
    *,
    output_path: Path,
    mongo_uri: str,
    mongo_database: str,
    mongo_collection: str,
    limit: int | None = None,
) -> dict[str, Any]:
    vulnerabilities = fetch_filtered_records(collection, state, limit=limit)
    payload = {
        "filtered_at": datetime.now(UTC).isoformat(),
        "mongo": {
            "uri": redact_mongo_uri(mongo_uri) or mongo_uri,
            "database": mongo_database,
            "collection": mongo_collection,
        },
        "filters": state.filters_payload(),
        "result_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


def strip_mongo_id(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result.pop("_id", None)
    return result


def _discover_object_keys(collection: Any, field_path: str, *, sample_size: int) -> set[str]:
    keys: set[str] = set()
    try:
        cursor = collection.find(
            {field_path: {"$type": "object"}},
            {field_path: 1},
        ).limit(sample_size)
    except Exception:
        return keys

    for document in cursor:
        metrics = _value_at_path(document, field_path)
        if isinstance(metrics, dict):
            keys.update(str(key) for key in metrics if key)
    return keys


def _value_at_path(document: dict[str, Any], field_name: str) -> Any:
    value: Any = document
    for part in field_name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _flatten(values: Any) -> list[Any]:
    if isinstance(values, list):
        result: list[Any] = []
        for value in values:
            result.extend(_flatten(value))
        return result
    return [values]
