from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo


LOCAL_TIMEZONE = ZoneInfo("Asia/Hong_Kong")

_DATETIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
)

_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%Y.%m.%d",
    "%d %b %Y",
    "%d %B %Y",
    "%b %d, %Y",
    "%B %d, %Y",
)


def today_start(tz: ZoneInfo = LOCAL_TIMEZONE) -> datetime:
    return datetime.combine(datetime.now(tz).date(), time.min, tzinfo=tz)


def window_start(days: int = 1, tz: ZoneInfo = LOCAL_TIMEZONE) -> datetime:
    """Inclusive calendar-day window ending today in ``tz`` (``days=1`` is today only)."""
    if days < 1:
        raise ValueError("days must be at least 1")
    return today_start(tz) - timedelta(days=days - 1)


def document_published_time(record: dict[str, Any]) -> str | None:
    return _document_timestamp(record, "published")


def document_updated_time(record: dict[str, Any]) -> str | None:
    return _document_timestamp(record, "updated")


def record_updated_at_or_after(record: dict[str, Any], boundary: datetime) -> bool | None:
    value = document_updated_time(record)
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return parsed >= boundary.astimezone(UTC)


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        parsed = _parse_text_timestamp(text)
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_TIMEZONE)
    return parsed.astimezone(UTC)


def normalize_timestamp(value: Any) -> str | None:
    parsed = parse_timestamp(value)
    return parsed.isoformat() if parsed is not None else None


def _document_timestamp(record: dict[str, Any], kind: str) -> str | None:
    from .schema_v2 import PROVIDER_SCHEMAS

    provider = str(record.get("type") or record.get("provider") or "").strip().lower()
    schema = PROVIDER_SCHEMAS.get(provider)
    envelope_field = "published_at" if kind == "published" else "updated_at"
    fields = getattr(schema, f"{kind}_fields", ()) if schema else ()
    details = record.get("details") if isinstance(record.get("details"), dict) else {}
    if isinstance(details.get(provider), dict):
        details = details[provider]
    candidates = [record.get(envelope_field)]
    candidates.extend(_path_value(details, path) for path in fields)
    if kind == "updated":
        candidates.append(record.get("published_at"))
        if schema:
            candidates.extend(_path_value(details, path) for path in schema.published_fields)
    candidates.append(record.get("disclosure_date"))
    for value in candidates:
        normalized = normalize_timestamp(value)
        if normalized is not None:
            return normalized
    return None


def _path_value(document: dict[str, Any], path: str) -> Any:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _parse_text_timestamp(text: str) -> datetime | None:
    compact = " ".join(text.split())
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(compact, fmt)
        except ValueError:
            pass
    for fmt in _DATE_FORMATS:
        try:
            parsed_date = datetime.strptime(compact, fmt).date()
            return datetime.combine(parsed_date, time.min)
        except ValueError:
            pass
    return None
