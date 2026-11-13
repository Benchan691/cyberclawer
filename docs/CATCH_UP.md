# Resumable catch-up

The existing hourly command remains valid:

```sh
vuln-scrape catch-up --days 1
```

`--days` is a rolling overlap **before saved progress**, not a filter starting at
midnight. Each provider has independent progress in `<news collection>_sync_state`
(normally `news_sync_state`) in the same MongoDB database. News documents keep
their existing schema, identities, collection and historical data.

## First run and progress

Without a saved position, a provider starts from its newest stored `updated_at`,
falling back to `published_at`. MongoDB dates, including naive BSON values, are
interpreted as UTC. Future positions are clamped to the current time. An empty
provider starts with its current feed or updates from the previous seven days.

Each request window has fixed UTC boundaries. Discovery progress and completed
progress are distinct: queued windows can continue discovering new updates while
older requests or writes remain unresolved. Completed progress advances only
after the associated advisory writes are acknowledged. Empty results count as
completion only when the source response verifies exhaustion.

The state collection contains provider documents, compact retry documents, and
listing fingerprints. Full pages and expanded monthly records live in checked,
immutable JSON snapshots under `data/sync-cache/<provider>`. Keep this directory
between invocations. A missing snapshot is replayed from its source; its saved
offset is never applied blindly to different data. Failed requests from the
legacy checkpoint are imported once, including failed NVD query windows.

Historical recovery is disabled. Saved archive cursors, baseline recovery work
and retries belonging to those scans are retired automatically. Incremental
windows, failed update requests, and existing news documents are preserved.

## Source strategies

| Sources | Behavior |
| --- | --- |
| NVD | Modification-date windows, each at most 120 days; fixed offsets and window boundaries across resumes. |
| GitHub Advisory | `modified` ranges, `sort=updated`, and validated `Link` pagination URLs. |
| CVE | Delta batch `fetchTime` is the arrival cursor. An older advisory `dateUpdated` does not exclude a new arrival. |
| FortiGuard, HPE | Reconcile the complete current RSS feed; full details are fetched even for old dates. FortiGuard remains RSS-only. |
| Splunk, Zimbra, MSRC | Read the full index and process recent or changed entries. Unchanged details are not revisited. MSRC child CVEs resume across limits. |
| AVD, CNVD, GOVCERT, HKCERT, Huawei SA, Palo Alto, Qianxin | Refresh recent listings. Stop after a whole page older than the saved overlap, using listing modification dates where available. No rotating archive scan. |

For sources without a modification filter, unchanged listing metadata avoids
an immediate detail fetch. Old missing advisories outside the update window are
skipped. A known entry whose listing metadata changes is still fetched, even if
its publication date is old. Missing dates are not proof that an entry is old.
Once an entry is selected, an old or missing detail-page date does not reject it.
Older revisions that do not change visible listing metadata are not discovered
through background detail scans.

## Limits and retries

* `--limit` defaults to 1,000 advisory checks per provider per invocation,
  including unchanged records and expanded MSRC children.
* The entire allowance is available to recent updates and retries. Every
  invocation polls the newest source head before pending failures or update
  pages; there is no historical-work allocation.
* `--batch-size` defaults to 5 and caps acknowledged write/checkpoint batches.
* `--max-runs-per-provider` defaults to 100 and bounds listing work per
  invocation. Cached pages can still be consumed without new listing requests.
* A non-blocking `data/catch-up.lock` prevents overlapping cron invocations.
  An overlapping invocation logs that it was skipped; it does not clear progress.

When CVE delta retention no longer covers a saved position, process the available
deltas and report the skipped coverage gap. No baseline is requested or downloaded.
RSS sources likewise reconcile their current feed without recovering entries
that have already disappeared. These accepted historical gaps do not keep the
recent-update status permanently partial.

News upserts are idempotent. Comparison respects BSON UTC/millisecond storage,
and an older pinned observation cannot replace a subsequently observed record.
Failed details never replace full documents with listing summaries. Database
write failures retain retry references; one failure does not prevent other
updates being collected. Records disappearing from a listing are retained.

## Operation and rollback

Per-provider logs report checked/fetched counts, incremental status, history
status (`disabled`), outside-window skips, pending windows/retries, and
insert/update/skip/error counts. `partial` and `error` are not caught-up states.
`up_to_date` means available incremental updates were processed; historical
coverage is not promised.

Back up the affected program files before deploying, preserve the server's
`.env`, `mongodb.toml`, `scrapers.toml` and cron entry, then compare two runs:
recent updates should be written, and an unchanged second run should skip matching
records and retain or advance progress without resuming an archive. Verify records
independently in MongoDB.
If rolling back program files, retain the state collection and cache: the older
program ignores them and no news schema migration is required.
