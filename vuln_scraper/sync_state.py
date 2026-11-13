"""Durable, sink-scoped catch-up positions and immutable work snapshots."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .models import ListEntry, VulnerabilityId

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SyncContext:
    overlap_days: int = 1
    batch_size: int = 5
    max_pages: int = 100
    since: datetime | None = None
    until: datetime | None = None
    cursor: str | None = None

    def __post_init__(self) -> None:
        if min(self.overlap_days, self.batch_size, self.max_pages) < 1:
            raise ValueError("overlap, batch size and listing request limit must be positive")


def utc(value: Any) -> datetime | None:
    """State and MongoDB datetimes are UTC, including naive BSON values."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def entry_data(entry: ListEntry) -> dict[str, Any]:
    return {
        "identity": {"type": entry.identity.type, "code": entry.identity.code},
        "title": entry.title, "vuln_type": entry.vuln_type,
        "disclosure_date": entry.disclosure_date, "status": entry.status,
        "provider": entry.provider, "source_url": entry.source_url,
        "embedded_detail": entry.embedded_detail,
    }


def restore_entry(data: dict[str, Any]) -> ListEntry:
    payload = dict(data)
    payload["identity"] = VulnerabilityId(**payload["identity"])
    return ListEntry(**payload)


def retry_entry_data(entry: ListEntry) -> dict[str, Any]:
    """Keep request provenance, not full inline advisories or credentials, in MongoDB."""
    payload = entry_data(entry)
    detail = entry.embedded_detail or {}
    payload["embedded_detail"] = {
        key: detail[key] for key in (
            "detail_url", "doc_id", "doc_display_url", "_github_link", "cvrf_url",
        ) if key in detail
    }
    payload["embedded_detail"]["_list_summary"] = True
    return payload


class SnapshotCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def path(self, digest: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid sync snapshot digest")
        return self.directory / f"{digest}.json"

    def write(self, value: Any) -> str:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        target = self.path(digest)
        if not target.exists():
            temporary = target.with_suffix(".tmp")
            temporary.write_bytes(encoded)
            temporary.replace(target)
        return digest

    def read(self, digest: str | None) -> Any | None:
        if not digest:
            return None
        path = self.path(digest)
        if not path.exists():
            return None
        encoded = path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != digest:
            logger.warning("Discarding corrupt sync snapshot %s; source work will be replayed", digest)
            path.unlink()
            return None
        return json.loads(encoded)

    def prune(self, referenced: set[str], now: datetime) -> None:
        cutoff = (now - timedelta(days=7)).timestamp()
        for path in self.directory.glob("*.json"):
            if path.stem not in referenced and path.stat().st_mtime < cutoff:
                path.unlink()


class SyncStateStore:
    def __init__(self, collection: Any, provider: str) -> None:
        self.collection = collection
        self.provider = provider
        collection.create_index([("provider", 1), ("kind", 1)], name="provider_work_kind")

    def load(self, news: Any, now: datetime) -> dict[str, Any]:
        state = self.collection.find_one({"_id": self.provider})
        if state is not None:
            if state.get("schema_version") != 1:
                raise ValueError(f"unsupported sync state version for {self.provider}")
            return state
        updated: datetime | None = None
        published: datetime | None = None
        count = 0
        query = {"$or": [
            {"source.provider": self.provider},
            {"_id": {"$regex": rf"^{re.escape(self.provider)}:"}},
        ]}
        for document in news.find(query, {"updated_at": 1, "published_at": 1}):
            count += 1
            value = utc(document.get("updated_at"))
            if value is not None:
                updated = max(updated, value) if updated else value
            value = utc(document.get("published_at"))
            if value is not None:
                published = max(published, value) if published else value
        seed = min(updated or published or (now - timedelta(days=7)), now)
        return {
            "_id": self.provider, "kind": "provider", "schema_version": 1,
            "provider": self.provider, "last_successful_until": seed.isoformat(),
            "discovered_until": seed.isoformat(), "scheduled_until": seed.isoformat(),
            "bootstrap_empty": count == 0, "tasks": [], "completed_intervals": [],
            "discovered_intervals": [], "archive": None, "history_gap": None,
        }

    def save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = datetime.now(UTC)
        result = self.collection.replace_one({"_id": self.provider}, state, upsert=True)
        if getattr(result, "acknowledged", True) is False:
            raise RuntimeError("sync state write was not acknowledged")

    def defer(self, identity: str, reference: dict[str, Any]) -> None:
        document = {**reference, "_id": f"{self.provider}:retry:{identity}",
                    "provider": self.provider, "kind": "retry", "identity": identity,
                    "failed_at": datetime.now(UTC).isoformat()}
        result = self.collection.replace_one({"_id": document["_id"]}, document, upsert=True)
        if getattr(result, "acknowledged", True) is False:
            raise RuntimeError("retry reference write was not acknowledged")

    def failures(self) -> list[dict[str, Any]]:
        return list(self.collection.find({"provider": self.provider, "kind": "retry"}))

    def clear(self, identity: str) -> None:
        result = self.collection.delete_one({"_id": f"{self.provider}:retry:{identity}"})
        if getattr(result, "acknowledged", True) is False:
            raise RuntimeError("retry acknowledgement was not committed")

    def advance(self, state: dict[str, Any], task: dict[str, Any], *, complete: bool) -> None:
        field = "completed_intervals" if complete else "discovered_intervals"
        position = "last_successful_until" if complete else "discovered_until"
        intervals = state[field] + [[task["since"], task["until"]]]
        intervals.sort(key=lambda pair: utc(pair[0]))
        merged: list[list[str]] = []
        for start, end in intervals:
            if merged and utc(start) <= utc(merged[-1][1]):
                if utc(end) > utc(merged[-1][1]):
                    merged[-1][1] = end
            else:
                merged.append([start, end])
        boundary = utc(state[position])
        remaining = []
        for start, end in merged:
            if utc(start) <= boundary:
                boundary = max(boundary, utc(end))
            else:
                remaining.append([start, end])
        state[field] = remaining
        state[position] = boundary.isoformat()


@contextmanager
def catch_up_lock(data_dir: Path) -> Iterator[bool]:
    """Prevent overlapping cron invocations from racing on shared progress."""
    import fcntl
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "catch-up.lock").open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
