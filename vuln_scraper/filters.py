from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from .config import MAX_RESULT_LIMIT


TYPE_CVE = "cve"
TYPE_NON_CVE = "non-cve"
TYPE_CHOICES = {TYPE_CVE, TYPE_NON_CVE}
AttributeFilter = tuple[str, str]
FIELD_ALIASES = {
    "id": "code",
    "vulnerability_id": "code",
}


def validate_limit(value: int) -> int:
    if not 1 <= value <= MAX_RESULT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
    return value


def parse_type_selection(value: str | None) -> tuple[bool, bool]:
    if not value:
        return True, True

    selected = {part.strip().lower() for part in value.split(",") if part.strip()}
    invalid = selected - TYPE_CHOICES
    if invalid:
        raise ValueError(f"invalid type(s): {', '.join(sorted(invalid))}")
    if not selected:
        raise ValueError("at least one type must be selected")

    return TYPE_CVE in selected, TYPE_NON_CVE in selected


def parse_attribute_filter(value: str) -> AttributeFilter:
    field, separator, expected = value.partition("=")
    field = field.strip()
    expected = expected.strip()
    normalized_field = _normalize_filter_path(field)
    if not separator or not normalized_field or not expected:
        raise ValueError("attribute filters must use field=value syntax")
    return normalized_field, expected


def parse_attribute_filters(values: Iterable[str] | None) -> tuple[AttributeFilter, ...]:
    if not values:
        return ()
    return tuple(parse_attribute_filter(value) for value in values)


def type_selection_label(include_cve: bool, include_non_cve: bool) -> str:
    selected = []
    if include_cve:
        selected.append(TYPE_CVE)
    if include_non_cve:
        selected.append(TYPE_NON_CVE)
    return ",".join(selected)


def record_has_cve(record: dict[str, Any]) -> bool:
    return record.get("cve_code") is not None


def record_matches_types(
    record: dict[str, Any],
    *,
    include_cve: bool,
    include_non_cve: bool,
) -> bool:
    has_cve = record_has_cve(record)
    return (has_cve and include_cve) or (not has_cve and include_non_cve)


def record_matches_attribute_filters(
    record: dict[str, Any],
    filters: Iterable[AttributeFilter],
) -> bool:
    for field_path, expected in filters:
        if not _record_matches_attribute_filter(record, _normalize_filter_path(field_path), expected):
            return False
    return True


def _record_matches_attribute_filter(
    record: dict[str, Any],
    field_path: str,
    expected: str,
) -> bool:
    expected_folded = expected.casefold()
    return any(
        expected_folded in str(value).casefold()
        for value in _values_at_path(record, field_path.split("."))
        if value is not None
    )


def _values_at_path(value: Any, parts: list[str]) -> Iterator[Any]:
    if not parts:
        yield from _leaf_values(value)
        return

    head, *tail = parts
    if isinstance(value, dict):
        key = _lookup_key(value, head)
        if key is not None:
            yield from _values_at_path(value[key], tail)
        return

    if isinstance(value, list):
        for item in value:
            yield from _values_at_path(item, parts)


def _leaf_values(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _leaf_values(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _leaf_values(item)
        return
    yield value


def _lookup_key(value: dict[str, Any], requested_key: str) -> str | None:
    if requested_key in value:
        return requested_key

    requested_folded = requested_key.casefold()
    for key in value:
        if key.casefold() == requested_folded:
            return key
    return None


def _normalize_filter_path(field_path: str) -> str:
    normalized = ".".join(part.strip() for part in field_path.split(".") if part.strip())
    alias_key = normalized.replace(".", "_").casefold()
    return FIELD_ALIASES.get(alias_key, normalized)
