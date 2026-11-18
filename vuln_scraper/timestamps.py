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


def window_start(
    days: int = 1, tz: ZoneInfo = LOCAL_TIMEZONE, *, now: datetime | None = None,
) -> datetime:
    """Inclusive calendar-day window ending today in ``tz`` (``days=1`` is today only)."""
    if days < 1:
        raise ValueError("days must be at least 1")
    start = today_start(tz) if now is None else datetime.combine(now.astimezone(tz).date(), time.min, tzinfo=tz)
    return start - timedelta(days=days - 1)


def publication_time(record: dict[str, Any]) -> datetime | None:
    """Resolve source publication evidence without treating an edit as publication."""
    published = parse_timestamp(record.get("published_at"))
    if published is not None:
        return published
    provider = str(record.get("type") or record.get("provider") or "").strip().lower()
    details = record.get("details")
    details = details if isinstance(details, dict) else {}
    if isinstance(details.get(provider), dict):
        details = details[provider]
    if isinstance(details, dict):
        precise = parse_timestamp(details.get("published_at"))
        if precise is not None:
            return precise
    # These providers put a modification date in the legacy disclosure slot.
    if provider in {"cve", "msrc", "qianxin"}:
        record = {**record, "disclosure_date": None}
    return parse_timestamp(document_published_time(record))


def source_news_time(record: dict[str, Any]) -> datetime | None:
    """Latest source publication/edit date; observation time is never news evidence."""
    dates = [publication_time(record), modification_time(record)]
    return max((value for value in dates if value is not None), default=None)


def modification_time(record: dict[str, Any]) -> datetime | None:
    """Resolve an edit date without mistaking an RSS publication fallback for one."""
    from .schema_v2 import PROVIDER_SCHEMAS

    provider = str(record.get("type") or record.get("provider") or "").strip().lower()
    details = record.get("details")
    details = details if isinstance(details, dict) else {}
    if isinstance(details.get(provider), dict):
        details = details[provider]
    dates = [parse_timestamp(record.get("updated_at")), parse_timestamp(details.get("updated_at"))]
    schema = PROVIDER_SCHEMAS.get(provider)
    for field in (schema.updated_fields if schema else ()):
        value = parse_timestamp(_path_value(details, field))
        if (details.get("_list_summary") and provider in {"fortiguard", "hpe", "wiz"}
                and field != "updated_at" and value == publication_time(record)):
            continue
        dates.append(value)
    if provider in {"cve", "msrc", "qianxin"} and not any(value is not None for value in dates):
        dates.append(parse_timestamp(record.get("disclosure_date")))
    return max((value for value in dates if value is not None), default=None)


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
