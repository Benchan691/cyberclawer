from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit


LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
}


def _configured_level() -> int:
    value = os.getenv("CLASSIFIER_LOG_LEVEL", "INFO").upper()
    return LEVELS.get(value, LEVELS["INFO"])


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if "@" not in parsed.netloc:
        return value
    credentials, host = parsed.netloc.rsplit("@", 1)
    username = credentials.split(":", 1)[0]
    redacted = f"{username}:***@{host}" if username else f"***@{host}"
    return urlunsplit((parsed.scheme, redacted, parsed.path, parsed.query, parsed.fragment))


def _safe_value(key: str, value: Any) -> Any:
    if isinstance(value, Exception):
        return str(value)
    if isinstance(value, str) and any(token in key.lower() for token in ("uri", "url")):
        return _redact_url(value)
    return value


def log_event(component: str, message: str, *, level: str = "INFO", **fields: Any) -> None:
    normalized_level = level.upper()
    if LEVELS.get(normalized_level, LEVELS["INFO"]) < _configured_level():
        return

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": normalized_level,
        "component": component,
        "message": message,
    }
    for key, value in fields.items():
        payload[key] = _safe_value(key, value)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str), flush=True)

