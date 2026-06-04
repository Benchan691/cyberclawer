from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_handler_lock = threading.Lock()


class ScraperErrorLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path

    @classmethod
    def for_settings(cls, data_dir: Path, error_log_name: str | None) -> ScraperErrorLog:
        if not error_log_name:
            return cls(None)
        name = Path(error_log_name.strip()).name
        if not name:
            return cls(None)
        return cls(Path(data_dir) / name)

    def append(
        self,
        *,
        provider: str,
        phase: str,
        identity: str,
        url: str,
        error: str,
        stop_reason: str | None = None,
    ) -> None:
        if self.path is None:
            return

        payload = {
            "record_type": "failure",
            "timestamp": datetime.now(UTC).isoformat(),
            "provider": provider,
            "phase": phase,
            "identity": identity,
            "url": url,
            "error": error,
        }
        if stop_reason is not None:
            payload["stop_reason"] = stop_reason

        line = json.dumps(payload, ensure_ascii=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def append_exception(
        self,
        *,
        provider: str,
        error: BaseException,
        phase: str = "run",
    ) -> None:
        self.append(
            provider=provider,
            phase=phase,
            identity="",
            url="",
            error=f"{type(error).__name__}: {error}",
        )


def log_uncaught_provider_error(
    *,
    data_dir: Path,
    error_log_name: str | None,
    provider: str,
    error: BaseException,
) -> None:
    ScraperErrorLog.for_settings(data_dir, error_log_name).append_exception(
        provider=provider,
        error=error,
    )


def install_run_log_handler(data_dir: Path, error_log_name: str | None) -> Path | None:
    if not error_log_name:
        return None
    name = Path(error_log_name.strip()).name
    if not name:
        return None

    path = Path(data_dir) / name
    resolved = path.resolve()
    root = logging.getLogger()
    with _handler_lock:
        for handler in root.handlers:
            if getattr(handler, "_vuln_scraper_log_path", None) == resolved:
                return path
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(_JSONLineLogFormatter())
        handler._vuln_scraper_log_path = resolved  # type: ignore[attr-defined]
        root.addHandler(handler)
        if root.getEffectiveLevel() > logging.INFO:
            root.setLevel(logging.INFO)
    return path


class _JSONLineLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "record_type": "log",
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)
