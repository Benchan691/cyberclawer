from __future__ import annotations

from datetime import UTC, date, datetime, time
from typing import Any
from zoneinfo import ZoneInfo


LOCAL_TIMEZONE = ZoneInfo("Asia/Hong_Kong")

_PUBLISHED_PATHS: dict[str, tuple[str, ...]] = {
    "avd": ("disclosure_date", "details.avd.attack_metrics.disclosure_date"),
    "hkcert": ("details.hkcert.release_date", "disclosure_date"),
    "cve": ("details.cve.published", "disclosure_date"),
    "cisco": ("details.cisco.first_published", "disclosure_date"),
    "zeroday": ("details.zeroday.disclosed_date", "disclosure_date"),
    "govcert": ("details.govcert.published_date", "disclosure_date"),
    "github_advisory": ("details.github_advisory.published_at", "disclosure_date"),
    "huawei_sa": ("details.huawei_sa.publishDate", "disclosure_date"),
    "paloalto": ("details.paloalto.published_date", "disclosure_date"),
    "qianxin": ("details.qianxin.published_date", "details.qianxin.published_at", "disclosure_date"),
    "ransomwarelive": ("details.ransomwarelive.attackdate", "disclosure_date"),
    "infosec": ("details.infosec.published_date", "disclosure_date"),
    "splunk": ("details.splunk.published_date", "disclosure_date"),
    "hikvision": (
        "details.hikvision.initial_release_date",
        "details.hikvision.published_date",
        "disclosure_date",
    ),
    "cnnvd": ("details.cnnvd.publishTime", "disclosure_date"),
    "cnvd": ("details.cnvd.published_date", "disclosure_date"),
    "juniper": ("details.juniper.published_date", "disclosure_date"),
    "msrc": ("details.msrc.initial_release_date", "disclosure_date"),
}

_UPDATED_PATHS: dict[str, tuple[str, ...]] = {
    "avd": ("disclosure_date",),
    "hkcert": ("details.hkcert.last_update_date", "details.hkcert.release_date", "disclosure_date"),
    "cve": ("details.cve.last_modified", "details.cve.published", "disclosure_date"),
    "cisco": ("details.cisco.last_updated", "details.cisco.first_published", "disclosure_date"),
    "zeroday": ("details.zeroday.patched_date", "details.zeroday.disclosed_date", "disclosure_date"),
    "govcert": ("details.govcert.published_date", "disclosure_date"),
    "github_advisory": (
        "details.github_advisory.updated_at",
        "details.github_advisory.published_at",
        "disclosure_date",
    ),
    "huawei_sa": ("details.huawei_sa.publishDate", "disclosure_date"),
    "paloalto": ("details.paloalto.updated_date", "details.paloalto.published_date", "disclosure_date"),
    "qianxin": (
        "details.qianxin.updated_date",
        "details.qianxin.updated_at",
        "details.qianxin.published_date",
        "details.qianxin.published_at",
        "disclosure_date",
    ),
    "ransomwarelive": (
        "details.ransomwarelive.discovered",
        "details.ransomwarelive.attackdate",
        "disclosure_date",
    ),
    "infosec": ("details.infosec.published_date", "disclosure_date"),
    "splunk": ("details.splunk.last_modified", "details.splunk.published_date", "disclosure_date"),
    "hikvision": (
        "details.hikvision.updated_date",
        "details.hikvision.initial_release_date",
        "details.hikvision.published_date",
        "disclosure_date",
    ),
    "cnnvd": ("details.cnnvd.updateTime", "details.cnnvd.publishTime", "disclosure_date"),
    "cnvd": ("details.cnvd.updated_date", "details.cnvd.published_date", "disclosure_date"),
    "juniper": ("details.juniper.updated_date", "details.juniper.published_date", "disclosure_date"),
    "msrc": ("details.msrc.current_release_date", "details.msrc.initial_release_date", "disclosure_date"),
}

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


def document_published_time(record: dict[str, Any]) -> str | None:
    return _document_timestamp(record, _PUBLISHED_PATHS)


def document_updated_time(record: dict[str, Any]) -> str | None:
    return _document_timestamp(record, _UPDATED_PATHS)


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


def _document_timestamp(record: dict[str, Any], mapping: dict[str, tuple[str, ...]]) -> str | None:
    provider = str(record.get("type") or "").strip().lower()
    for path in mapping.get(provider, ("disclosure_date",)):
        value = _path_value(record, path)
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
