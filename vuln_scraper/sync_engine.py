"""Incremental discovery, acknowledged batches and resumable retries."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from .client import FetchError
from .models import ListPage
from .mongo import MongoSyncResult, sync_records_to_collection
from .sync_state import SnapshotCache, SyncStateStore, entry_data, restore_entry, retry_entry_data, utc
from .timestamps import document_updated_time, parse_timestamp

logger = logging.getLogger(__name__)
FEEDS = {"fortiguard", "hpe"}
INDEXES = {"splunk", "zimbra", "msrc"}
WINDOWS = {"nvd", "github_advisory", "cve"}
HISTORY_TASKS = {"archive", "baseline", "index_audit"}


class SyncEngine:
    def __init__(self, runner: Any, news: Any, state_collection: Any) -> None:
        self.runner = runner
        self.news = news
        self.provider = runner.provider
        self.options = runner.sync_context
        self.now = utc(self.options.until) or datetime.now(UTC)
        self.store = SyncStateStore(state_collection, self.provider.key)
        self.state = self.store.load(news, self.now)
        self.cache = SnapshotCache(runner.settings.data_dir / "sync-cache" / self.provider.key)
        self.limit = runner.settings.limit
        self.checked = 0
        self.outside_window = 0
        self.pages = 0
        self.total_records: int | None = None
        self.seen: dict[str, datetime] = {}
        self.new_tasks: set[str] = set()
        self.list_cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.initial_failures = self.store.failures()
        self.result = MongoSyncResult()
        self.list_errors: list[str] = []
        self.failed_tasks: set[str] = set()

    def task(self, kind: str, since: datetime, until: datetime, **extra: Any) -> dict[str, Any]:
        return {"id": uuid4().hex, "kind": kind, "since": since.isoformat(),
                "until": until.isoformat(), "page": 1, "cursor": None,
                "index": 0, "cache": None, "child_cache": None,
                "child_index": 0, "enumerated": False, **extra}

    def schedule(self) -> None:
        self.discard_history_work()
        if not self.state.get("legacy_failures_imported"):
            self.import_failures()
            self.state["legacy_failures_imported"] = True
        anchor = min(utc(self.state["scheduled_until"]), self.now)
        since = anchor - timedelta(days=self.options.overlap_days)
        if self.state.get("bootstrap_empty") and not self.state.get("discovery_started"):
            since = anchor
        self.state["discovery_started"] = True
        if self.provider.key in WINDOWS:
            if self.now > anchor:
                while since < self.now:
                    end = min(since + timedelta(days=120), self.now) if self.provider.key == "nvd" else self.now
                    task = self.task("window", since, end)
                    self.state["tasks"].append(task)
                    self.new_tasks.add(task["id"])
                    since = end
        else:
            task = self.task("head", since, self.now)
            self.state["tasks"].append(task)
            self.new_tasks.add(task["id"])
        self.state["scheduled_until"] = self.now.isoformat()
        self.store.save(self.state)

    def discard_history_work(self) -> None:
        """Retire old recovery cursors without discarding incremental work or news."""
        history = [task for task in self.state["tasks"] if task["kind"] in HISTORY_TASKS]
        if self.state.get("archive"):
            history.append(self.state["archive"])
        history_ids = {task["id"] for task in history}
        for reference in self.store.failures():
            if reference.get("task_id") in history_ids:
                self.store.clear(reference["identity"])
                self.runner.checkpoint.failed.pop(reference["identity"], None)
        for identity in history_ids:
            self.runner.checkpoint.failed.pop(f"{self.provider.key}:LIST-{identity}", None)
        self.state["tasks"] = [task for task in self.state["tasks"] if task["kind"] not in HISTORY_TASKS]
        self.state["archive"] = None
        self.state["history_policy"] = "disabled"
        self.state.pop("index_audit_offset", None)
        previous_gap = self.state.pop("history_gap", None)
        if previous_gap:
            self.state["skipped_history_gap"] = previous_gap
        recovery_since = self.state.pop("recovery_since", None)
        if self.provider.key == "cve" and recovery_since:
            starts = [utc(task["since"]) for task in self.state["tasks"] if task["kind"] == "window"]
            # Earlier versions shortened a delta window and waited for a baseline
            # to bridge this gap. That history is now explicitly waived.
            if starts and utc(self.state["last_successful_until"]) < min(starts):
                gap = {"since": self.state["last_successful_until"], "until": min(starts).isoformat()}
                self.note_history_gap(gap["since"], gap["until"], "CVE delta retention")
                self.store.advance(self.state, gap, complete=False)
                self.store.advance(self.state, gap, complete=True)
        self.initial_failures = self.store.failures()

    def note_history_gap(self, since: str, until: str, reason: str) -> None:
        gap = {"since": since, "until": until, "reason": reason}
        if self.state.get("skipped_history_gap") != gap:
            logger.warning("%s historical recovery disabled; skipping coverage gap %s to %s (%s)",
                           self.provider.key, since, until, reason)
        self.state["skipped_history_gap"] = gap

    @staticmethod
    def listing_time(entry: Any) -> datetime | None:
        dates = [parse_timestamp(document_updated_time(entry.to_record())),
                 parse_timestamp(entry.disclosure_date)]
        return max((value for value in dates if value is not None), default=None)

    def import_failures(self) -> None:
        from .models import ListEntry, VulnerabilityId
        for failure in self.runner.checkpoint.failed.values():
            identity = str(failure.get("identity", ""))
            if not identity.startswith(f"{self.provider.key}:"):
                continue
            if self.provider.key == "nvd" and failure.get("phase") == "list":
                from urllib.parse import parse_qs, urlparse
                from .scrapers.nvd.config import LIST_URL
                target = urlparse(str(failure.get("url", "")))
                expected = urlparse(LIST_URL)
                if (target.scheme, target.netloc, target.path) == (expected.scheme, expected.netloc, expected.path):
                    query = parse_qs(target.query)
                    start = utc((query.get("lastModStartDate") or [None])[0])
                    end = utc((query.get("lastModEndDate") or [None])[0])
                    if start and end and timedelta(0) < end - start <= timedelta(days=120):
                        for field in ("last_successful_until", "discovered_until", "scheduled_until"):
                            self.state[field] = min(utc(self.state[field]), start).isoformat()
                continue
            if failure.get("phase") != "detail":
                continue
            if failure.get("entry"):
                entry = restore_entry(failure["entry"])
            else:
                code = str(failure.get("code") or identity.partition(":")[2])
                identity_type = failure.get("type") or ("GHSA" if self.provider.key == "github_advisory" else self.provider.key.upper())
                entry = ListEntry(VulnerabilityId(identity_type, code), code,
                                  None, None, None, self.provider.key, self.provider.source_url,
                                  {"_list_summary": True})
            self.store.defer(identity, {"entry": retry_entry_data(entry), "task_id": None,
                                        "error": str(failure.get("error", "previous failure"))[:2000]})
        self.initial_failures = self.store.failures()

    def signature(self, entry: Any) -> str:
        return hashlib.sha256(json.dumps(entry_data(entry), sort_keys=True, default=str).encode()).hexdigest()

    def ledger(self, identity: str) -> dict[str, Any] | None:
        return self.store.collection.find_one({"_id": f"{self.provider.key}:item:{identity}"})

    def mark(self, entry: Any, observed_at: str) -> None:
        identity = f"{self.provider.key}:item:{entry.key}"
        previous = self.ledger(entry.key)
        if previous and utc(previous.get("observed_at")) and utc(previous["observed_at"]) > utc(observed_at):
            return
        result = self.store.collection.replace_one({"_id": identity}, {
            "_id": identity, "kind": "item", "provider": self.provider.key,
            "signature": self.signature(entry), "checked_at": self.now, "observed_at": observed_at,
        }, upsert=True)
        if getattr(result, "acknowledged", True) is False:
            raise RuntimeError("advisory fingerprint write was not acknowledged")

    async def run(self, client: Any) -> dict[str, Any]:
        self.schedule()
        self.client = client
        fresh = sorted((task for task in self.state["tasks"] if task["id"] in self.new_tasks),
                       key=lambda task: task["until"], reverse=True)
        # Poll the newest source head before servicing old failures or backlog.
        fresh_allowance = self.limit if not self.initial_failures and len(self.state["tasks"]) == len(fresh) else max(1, self.limit // 2)
        await self.run_tasks(fresh, fresh_allowance)
        await self.retry_failures(max(0, self.limit - self.checked))
        pending = [task for task in self.state["tasks"] if task["id"] not in self.new_tasks and not task.get("enumerated") and not task.get("superseded")]
        await self.run_tasks(pending, max(0, self.limit - self.checked))
        # Use spare capacity for incremental work left after the newest poll.
        await self.run_tasks([task for task in self.state["tasks"] if not task.get("enumerated")],
                             max(0, self.limit - self.checked))
        await self.finish_tasks()
        failures = self.store.failures()
        if not self.state["tasks"] and not failures:
            self.state["bootstrap_complete"] = True
        self.state["pending_retries"] = len(failures)
        self.state["last_run"] = {"at": self.now, "checked": self.checked,
                                  "listing_requests": self.pages, "outside_window": self.outside_window,
                                  "history_status": "disabled", "mongo_sync": self.result.to_dict()}
        self.store.save(self.state)
        referenced = {task.get(key) for task in self.state["tasks"]
                      for key in ("cache", "child_cache") if task.get(key)}
        referenced.update(item["cache"] for item in failures if item.get("cache"))
        self.cache.prune(referenced, self.now)
        self.runner.mongo_result = self.result
        self.runner.selection_finalized = True
        unfinished = bool(self.state["tasks"] or failures)
        error = bool(self.list_errors or self.runner.run_failed or self.result.errors)
        self.runner.stop_reason = "error" if error else "limit" if unfinished else "exhausted"
        output = self.runner._build_output()
        output["total"] = self.total_records if self.total_records is not None else len(self.runner.records_by_id)
        output["mongo_sync"] = self.result.to_dict()
        output["sync"] = {
            "checked": self.checked, "listing_requests": self.pages, "outside_window": self.outside_window,
            "last_successful_until": self.state["last_successful_until"],
            "discovered_until": self.state["discovered_until"],
            "pending_windows": len(self.state["tasks"]), "pending_retries": len(failures),
            "incremental_status": "error" if error else "partial" if unfinished else "up_to_date",
            "history_status": "disabled",
            "history_gap": self.state.get("skipped_history_gap"),
            "archive_cursor": None,
        }
        self.runner.checkpoint.save(self.runner.settings.checkpoint_file)
        return output

    async def run_tasks(self, tasks: list[dict[str, Any]], allowance: int) -> None:
        target = min(self.limit, self.checked + allowance)
        for task in list(tasks):
            if self.checked >= target:
                break
            if self.pages >= self.options.max_pages and not task.get("cache"):
                continue
            if task.get("enumerated") or task.get("superseded") or task["id"] in self.failed_tasks:
                continue
            try:
                await self.process(task, target)
            except (FetchError, ValueError, RuntimeError) as exc:
                task["error"] = str(exc)[:2000]
                self.failed_tasks.add(task["id"])
                self.list_errors.append(task["error"])
                self.runner._record_failure(f"{self.provider.key}:LIST-{task['id']}",
                                            task.get("last_url", self.provider.source_url), exc, phase="list")
                logger.error("%s sync work remains pending: %s", self.provider.key, exc)
                self.store.save(self.state)

    async def page(self, task: dict[str, Any]) -> dict[str, Any] | None:
        payload = self.cache.read(task.get("cache"))
        if payload is not None:
            self.total_records = payload.get("total_records")
            return payload
        if self.pages >= self.options.max_pages:
            return None
        context = replace(self.options, since=utc(task["since"]), until=utc(task["until"]), cursor=task.get("cursor"))
        self.runner._active_sync_context = context
        if task["kind"] == "retry_parent":
            parsed = ListPage(page=1, entries=[restore_entry(task["retry_entry"])], total_pages=1)
            url = "saved advisory request"
        else:
            factory = getattr(self.provider, "sync_list_url", None)
            url = factory(context, task["page"]) if factory else self.provider.list_url(task["page"], checkpoint=self.runner.checkpoint)
            key = (url, task["page"], context.cursor, context.since if self.provider.key in WINDOWS else None,
                   context.until if self.provider.key in WINDOWS else None)
            if key in self.list_cache:
                payload = self.list_cache[key]
                self.total_records = payload.get("total_records")
                task["cache"] = self.cache.write(payload)
                task["index"] = 0
                self.store.save(self.state)
                return payload
            self.pages += 1
            task["last_url"] = url
            logger.info("Fetching %s sync %s list page %s", self.provider.key, task["kind"], task["page"])
            parsed = await self.runner._fetch_list_page(self.client, url, task["page"])
            if not parsed.entries and not parsed.exhausted:
                raise FetchError(f"Unverified empty {self.provider.key} list at {url}")
        self.runner.checkpoint.failed.pop(f"{self.provider.key}:LIST-{task['id']}", None)
        payload = {"entries": [entry_data(entry) for entry in parsed.entries],
                   "page": parsed.page, "total_pages": parsed.total_pages,
                   "total_records": parsed.total_records, "next_cursor": parsed.next_cursor,
                   "coverage_start": parsed.coverage_start, "observed_at": datetime.now(UTC).isoformat(),
                   "exhausted": parsed.exhausted, "url": url}
        self.total_records = parsed.total_records
        task["index"] = 0  # Missing local caches must replay, never trust their previous offset.
        if task["kind"] != "retry_parent":
            self.list_cache[key] = payload
        task["cache"] = self.cache.write(payload)
        task.pop("error", None)
        self.store.save(self.state)
        if self.provider.key == "cve" and parsed.coverage_start:
            earliest = utc(parsed.coverage_start)
            if earliest and max(utc(task["since"]), utc(self.state["last_successful_until"])) < earliest:
                self.note_history_gap(task["since"], min(earliest, utc(task["until"])).isoformat(),
                                      "CVE delta retention")
                self.store.save(self.state)
        if (self.provider.key in FEEDS and parsed.entries
                and (not self.state.get("bootstrap_empty") or self.state.get("bootstrap_complete"))):
            dates = [parse_timestamp(entry.disclosure_date) for entry in parsed.entries]
            dates = [value for value in dates if value is not None]
            if dates and min(dates) > utc(task["since"]):
                self.note_history_gap(task["since"], min(dates).isoformat(), "RSS history is bounded")
        # Identical snapshots resume their existing offset instead of starving the tail.
        if self.provider.key in FEEDS | INDEXES and task["kind"] == "head":
            version = self.signature_payload(payload["entries"])
            task["version"] = version
            for previous in self.state["tasks"]:
                if previous is not task and not previous.get("enumerated") and previous.get("version") == version:
                    previous_page = self.cache.read(previous.get("cache"))
                    if self.provider.key in INDEXES and previous.get("ordered") and previous_page is not None:
                        payload = previous_page
                        task["cache"] = previous["cache"]
                        task["ordered"] = True
                    for field in ("index", "child_cache", "child_index"):
                        task[field] = previous.get(field, 0 if field != "child_cache" else None)
                    if self.provider.key in INDEXES and not task.get("ordered"):
                        task["index"] = 0
                    task["since"] = previous["since"]
                    previous["superseded"] = True
        return payload

    @staticmethod
    def signature_payload(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()

    async def process(self, task: dict[str, Any], target: int) -> None:
        while self.checked < target and not task.get("enumerated"):
            payload = await self.page(task)
            if payload is None:
                return
            entries = payload["entries"]
            if task["kind"] == "head" and self.provider.key in INDEXES and not task.get("ordered"):
                changed = []
                for data in entries:
                    entry = restore_entry(data)
                    ledger = self.ledger(entry.key)
                    if not ledger or ledger.get("signature") != self.signature(entry):
                        changed.append(data)
                entries = changed
                payload = {**payload, "entries": changed}
                task["cache"] = self.cache.write(payload)
                task["ordered"] = True
                self.store.save(self.state)
            while task["index"] < len(entries) and self.checked < target:
                entry = restore_entry(entries[task["index"]])
                if task.get("seek_anchor"):
                    if entry.key == task["seek_anchor"]:
                        task.pop("seek_anchor")
                    task["index"] += 1
                    continue
                if (entry.key in self.seen and not task.get("child_cache")
                        and self.seen[entry.key] >= utc(payload["observed_at"])):
                    task["index"] += 1
                    continue
                ledger = self.ledger(entry.key)
                if (task["kind"] == "head" and self.provider.key not in FEEDS | WINDOWS
                        and not task.get("child_cache")):
                    listed_at = self.listing_time(entry)
                    changed = ledger and ledger.get("signature") != self.signature(entry)
                    if listed_at is not None and listed_at < utc(task["since"]) and not changed:
                        self.outside_window += 1
                        task["index"] += 1
                        self.store.save(self.state)
                        continue
                # Overlapping windows can contain the same already-acknowledged
                # observation. Drain that queued work without spending the next
                # run's allowance on replaying it instead of unfinished entries.
                if (task["id"] not in self.new_tasks and not task.get("child_cache")
                        and ledger and utc(ledger.get("observed_at"))
                        and utc(ledger["observed_at"]) >= utc(payload["observed_at"])):
                    task["index"] += 1
                    continue
                metadata_unchanged = (self.provider.key not in FEEDS and task["kind"] == "head"
                                      and ledger and ledger.get("signature") == self.signature(entry)
                                      and self.news.find_one({"_id": entry.key}) is not None)
                if metadata_unchanged:
                    self.checked += 1
                    self.seen[entry.key] = utc(ledger.get("observed_at")) or datetime.min.replace(tzinfo=UTC)
                    self.result.skipped += 1
                    self.result.unchanged += 1
                    task["index"] += 1
                    self.store.save(self.state)
                    continue
                done = await self.process_entry(task, entry, payload, target)
                if not done:
                    return
                task["anchor"] = entry.key
                task["index"] += 1
                self.store.save(self.state)
            if task["index"] < len(entries):
                return
            last = payload["total_pages"] is not None and task["page"] >= payload["total_pages"]
            if self.provider.key in {"github_advisory"}:
                last = not payload["next_cursor"]
            # A whole page older than the saved overlap ends recent discovery.
            # Use listing modification dates where the provider exposes them.
            if task["kind"] == "head" and self.provider.key not in FEEDS | INDEXES | WINDOWS:
                dates = [self.listing_time(restore_entry(data)) for data in entries]
                if dates and all(value is not None and value < utc(task["since"]) for value in dates):
                    last = True
            if last or payload["exhausted"]:
                task["enumerated"] = True
                if task.get("seek_anchor"):
                    task.pop("seek_anchor")
                    task["page"], task["index"], task["cache"] = 1, 0, None
                    task["enumerated"] = False
                    return
                if task["kind"] != "retry_parent":
                    self.store.advance(self.state, task, complete=False)
                self.store.save(self.state)
                return
            task["page"] += 1
            task["cursor"] = payload["next_cursor"]
            task["cache"], task["index"] = None, 0
            self.store.save(self.state)

    async def process_entry(self, task: dict[str, Any], entry: Any,
                            payload: dict[str, Any], target: int) -> bool:
        child = self.cache.read(task.get("child_cache"))
        if child is None:
            task["child_index"] = 0
            self.runner.records_by_id.pop(entry.key, None)
            self.runner.expanded_entry_ids.pop(entry.key, None)
            self.runner.run_failed.pop(entry.key, None)
            inline = entry.embedded_detail
            if isinstance(inline, dict) and not inline.get("_list_summary"):
                records = [entry.to_record(inline, detail_url=self.runner._detail_url_for_entry(entry))]
                observed = payload["observed_at"]
            else:
                await self.runner._scrape_detail(self.client, entry)
                observed = datetime.now(UTC).isoformat()
                if entry.key in self.runner.run_failed:
                    self.checked += 1
                    self.seen[entry.key] = utc(observed)
                    self.store.defer(entry.key, {"task_id": task["id"], "entry": retry_entry_data(entry),
                        "error": self.runner.run_failed[entry.key]["error"][:2000]})
                    return True
                ids = self.runner._record_ids_for_entry(entry)
                if self.provider.key == "msrc" and entry.key not in self.runner.expanded_entry_ids:
                    ids = []
                records = [self.runner.records_by_id[identity] for identity in ids if identity in self.runner.records_by_id]
            child = {"records": records, "observed_at": observed}
            task["child_cache"] = self.cache.write(child)
            self.store.save(self.state)
        records = child["records"]
        while task["child_index"] < len(records) and self.checked < target:
            offset = task["child_index"]
            size = min(self.options.batch_size, target - self.checked, len(records) - offset)
            batch = records[offset:offset + size]
            await self.write_batch(task, entry, child, batch, offset)
            task["child_index"] += size
            self.checked += size
            self.store.save(self.state)
        if task["child_index"] < len(records):
            return False
        self.seen[entry.key] = utc(child["observed_at"])
        if not any(item.get("entry", {}).get("identity") == entry_data(entry)["identity"] for item in self.store.failures()):
            self.mark(entry, child["observed_at"])
        task["child_cache"], task["child_index"] = None, 0
        return True

    async def write_batch(self, task: dict[str, Any], entry: Any, child: dict[str, Any],
                          batch: list[dict[str, Any]], offset: int) -> None:
        current = []
        for record in batch:
            identity = f"{record['type']}:{record['code']}"
            stored = self.news.find_one({"_id": identity})
            # A pinned older page must not overwrite a subsequently observed version.
            if stored and utc(stored.get("observed_at")) and utc(stored["observed_at"]) > utc(child["observed_at"]):
                self.result.skipped += 1
                continue
            current.append(record)
        result = sync_records_to_collection(current, self.runner.settings, self.news,
            scraped_at=child["observed_at"], source={"provider": self.provider.key, "url": self.provider.source_url})
        for key in ("inserted", "overwritten", "deleted", "skipped", "conflicts", "unchanged"):
            setattr(self.result, key, getattr(self.result, key) + getattr(result, key))
        self.result.errors.extend(result.errors)
        errors = {item["identity"]: item for item in result.errors}
        for index, record in enumerate(batch, offset):
            identity = f"{record['type']}:{record['code']}"
            if identity in errors:
                self.store.defer(identity, {"task_id": task["id"], "entry": retry_entry_data(entry),
                    "cache": task["child_cache"], "record_index": index,
                    "error": str(errors[identity]["error"])[:2000]})
            else:
                self.store.clear(identity)
                self.runner.records_by_id[identity] = record
                if identity not in self.runner.selected_ids:
                    self.runner.selected_ids.append(identity)

    async def retry_failures(self, allowance: int) -> None:
        target = min(self.limit, self.checked + allowance)
        for reference in self.initial_failures:
            if self.checked >= target:
                return
            entry = restore_entry(reference["entry"])
            identity = reference["identity"]
            cached = self.cache.read(reference.get("cache"))
            required_observation = utc((cached or {}).get("observed_at") or reference.get("failed_at"))
            if entry.key in self.seen and required_observation and self.seen[entry.key] >= required_observation:
                # Clear old parent failures if a fresh observation succeeded.
                if entry.key not in self.runner.run_failed and identity not in {item["identity"] for item in self.result.errors} and self.news.find_one({"_id": identity}):
                    self.store.clear(identity)
                continue
            task = self.task("retry", utc(self.state["last_successful_until"]), self.now)
            task["id"] = reference.get("task_id")
            if cached is not None and reference.get("record_index", 0) < len(cached["records"]):
                index = reference.get("record_index", 0)
                task["child_cache"] = reference["cache"]
                await self.write_batch(task, entry, cached, [cached["records"][index]], index)
                self.checked += 1
            else:
                # Missing caches are recoverable from the saved parent request.
                done = await self.process_entry(task, entry, {"observed_at": self.now.isoformat()}, target)
                if not done:
                    task["kind"] = "retry_parent"
                    task["id"] = uuid4().hex
                    task["retry_entry"] = entry_data(entry)
                    task["cache"] = self.cache.write({"entries": [entry_data(entry)], "page": 1,
                        "total_pages": 1, "total_records": 1, "next_cursor": None, "exhausted": False,
                        "observed_at": self.now.isoformat(), "coverage_start": None, "url": "saved retry"})
                    self.state["tasks"].append(task)
                elif entry.key not in self.runner.run_failed:
                    self.store.clear(identity)
            self.store.save(self.state)

    async def finish_tasks(self) -> None:
        failures = self.store.failures()
        failed_tasks = {item.get("task_id") for item in failures}
        remaining = []
        for task in self.state["tasks"]:
            if task.get("superseded"):
                continue
            if task.get("enumerated") and task["id"] not in failed_tasks and not failures:
                if task["kind"] != "retry_parent":
                    self.store.advance(self.state, task, complete=True)
            else:
                remaining.append(task)
        self.state["tasks"] = remaining
