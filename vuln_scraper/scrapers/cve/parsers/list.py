from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId, normalize_cve_code
from vuln_scraper.scrapers.cve.config import SOURCE_URL


@dataclass(frozen=True, slots=True)
class CVEDeltaEntry:
    action: str
    cve_id: str
    github_link: str | None
    cve_org_link: str | None
    date_updated: str | None

    @property
    def code(self) -> str:
        normalized = normalize_cve_code(self.cve_id)
        if normalized is None:
            raise ValueError(f"invalid CVE identifier: {self.cve_id!r}")
        return normalized

    @property
    def identity(self) -> str:
        return f"cve:{self.code}"


@dataclass(frozen=True, slots=True)
class CVEDeltaBatch:
    fetch_time: str
    entries: tuple[CVEDeltaEntry, ...]


def parse_cve_list_updated_since(
    data: Any,
    *,
    updated_since: datetime,
    page: int,
    provider: str = "cve",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    boundary = (
        updated_since.astimezone(UTC)
        if updated_since.tzinfo is not None
        else updated_since.replace(tzinfo=UTC)
    )
    batches = parse_cve_delta_log(data, after="1970-01-01T00:00:00Z")
    candidates: list[tuple[datetime, ListEntry]] = []
    for batch in reversed(batches):
        for delta_entry in batch.entries:
            if delta_entry.action == "deleted":
                continue
            updated_at = _delta_entry_updated_at(delta_entry, batch.fetch_time)
            if updated_at is None or updated_at < boundary:
                continue
            candidates.append(
                (
                    updated_at,
                    cve_delta_entry_to_list_entry(
                        delta_entry,
                        provider=provider,
                        source_url=source_url,
                    ),
                )
            )

    candidates.sort(key=lambda item: item[0], reverse=True)
    entries = [entry for _, entry in candidates]
    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        start_index=0,
        results_per_page=len(entries),
    )


def _delta_entry_updated_at(delta_entry: CVEDeltaEntry, batch_fetch_time: str) -> datetime | None:
    if delta_entry.date_updated:
        return parse_cve_datetime(delta_entry.date_updated)
    try:
        return parse_cve_datetime(batch_fetch_time)
    except ValueError:
        return None


def parse_cve_list(
    data: Any,
    *,
    page: int,
    provider: str = "cve",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    batches = parse_cve_delta_log(data, after="1970-01-01T00:00:00Z")
    entries: list[ListEntry] = []
    for batch in reversed(batches):
        for delta_entry in batch.entries:
            if delta_entry.action == "deleted":
                continue
            entries.append(
                cve_delta_entry_to_list_entry(
                    delta_entry,
                    provider=provider,
                    source_url=source_url,
                )
            )

    return ListPage(
        page=page,
        entries=entries,
        total_pages=1,
        total_records=len(entries),
        start_index=0,
        results_per_page=len(entries),
    )


def cve_delta_entry_to_list_entry(
    delta_entry: CVEDeltaEntry,
    *,
    provider: str = "cve",
    source_url: str | None = SOURCE_URL,
) -> ListEntry:
    return ListEntry(
        identity=VulnerabilityId(type="CVE", code=delta_entry.code),
        title=delta_entry.cve_id,
        vuln_type=None,
        disclosure_date=delta_entry.date_updated,
        status=delta_entry.action,
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "_delta_action": delta_entry.action,
            "_github_link": delta_entry.github_link,
        },
    )


def parse_cve_delta_log(data: Any, *, after: str) -> list[CVEDeltaBatch]:
    payload = _coerce_json(data)
    if not isinstance(payload, list):
        raise ValueError("CVE delta log must be a JSON array")

    cutoff = parse_cve_datetime(after)
    batches: list[tuple[datetime, CVEDeltaBatch]] = []
    for raw_batch in payload:
        if not isinstance(raw_batch, dict):
            raise ValueError("CVE delta batch must be a JSON object")
        fetch_time = _required_text(raw_batch.get("fetchTime"), "delta batch fetchTime")
        parsed_fetch_time = parse_cve_datetime(fetch_time)
        if parsed_fetch_time <= cutoff:
            continue

        entries: list[CVEDeltaEntry] = []
        for action in ("new", "updated", "deleted"):
            raw_entries = raw_batch.get(action) or []
            if not isinstance(raw_entries, list):
                raise ValueError(f"CVE delta batch {action} must be an array")
            for raw_entry in raw_entries:
                if not isinstance(raw_entry, dict):
                    raise ValueError(f"CVE delta {action} entry must be an object")
                cve_id = _required_text(raw_entry.get("cveId"), f"CVE delta {action} cveId")
                if normalize_cve_code(cve_id) is None:
                    raise ValueError(f"invalid CVE delta identifier: {cve_id!r}")
                github_link = _optional_text(raw_entry.get("githubLink"))
                if action != "deleted" and github_link is None:
                    raise ValueError(f"CVE delta {action} entry {cve_id} has no githubLink")
                entries.append(
                    CVEDeltaEntry(
                        action=action,
                        cve_id=cve_id,
                        github_link=github_link,
                        cve_org_link=_optional_text(raw_entry.get("cveOrgLink")),
                        date_updated=_optional_text(raw_entry.get("dateUpdated")),
                    )
                )

        batches.append(
            (
                parsed_fetch_time,
                CVEDeltaBatch(fetch_time=fetch_time, entries=tuple(entries)),
            )
        )
    return [batch for _, batch in sorted(batches, key=lambda item: item[0])]


def parse_cve_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _required_text(value: Any, field: str) -> str:
    text = _optional_text(value)
    if text is None:
        raise ValueError(f"{field} is required")
    return text


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
