# Resumable catch-up

The existing hourly command remains valid:

```sh
vuln-scrape catch-up --days 1
```

`--days 1` accepts only articles published or updated **today in Hong Kong time**,
starting at local midnight. `--days 2` explicitly includes yesterday and today.
This rule applies to every provider in both `run` and `catch-up`; RSS feeds have
no date exemption. Scrape/observation time and RSS build time never make old
news eligible. Each provider has independent progress in `<news collection>_sync_state`
(normally `news_sync_state`) in the same MongoDB database. News documents keep
their existing schema, identities, collection and historical data.

## First run and progress

Every run starts discovery inside the requested calendar window, including for
an empty provider or after a long outage. There is no seven-day bootstrap or
catch-up of older days. Existing positions are clamped to the current boundary.
MongoDB state dates, including naive BSON values, are interpreted as UTC. NVD's
full UTC publication/edit timestamps are preserved so updates after 16:00 UTC
are correctly included in the following Hong Kong calendar day.

Each request window has fixed UTC boundaries. Discovery progress and completed
progress are distinct: queued windows can continue discovering new updates while
eligible requests or writes remain unresolved. Completed progress advances only
after the associated advisory writes are acknowledged. Empty results count as
completion only when the source response verifies exhaustion.

The state collection contains provider documents, compact retry documents, and
listing fingerprints. Full pages and expanded monthly records live in checked,
immutable JSON snapshots under `data/sync-cache/<provider>`. Keep this directory
between invocations. A missing snapshot is replayed from its source; its saved
offset is never applied blindly to different data. Legacy failures are imported
once, then filtered by the current date window. Old NVD failures cannot rewind
the request boundary.

Historical recovery is disabled. Saved archive cursors, baseline recovery work
and retries belonging to those scans are retired automatically. Queued windows
and retry payloads from older days also expire. Existing news documents remain
stored; changing the scrape window does not delete historical data.

## Source strategies

| Sources | Behavior |
| --- | --- |
| NVD | Modification-date queries bounded by the requested window; returned records must pass the shared source-date check. |
| GitHub Advisory | Bounded `modified` ranges, `sort=updated`, and validated `Link` pagination URLs; the shared date guard also applies. |
| CVE | Delta arrival discovers candidates; publication/update dates determine eligibility. Old arrivals are not saved just because they appear in a new batch. |
| FortiGuard, HPE, Wiz | Read the current RSS feed and verify article publication/edit dates. RSS publication alone cannot rule out a new article edit. Old unchanged details are not saved. FortiGuard remains RSS-only. |
| Splunk, Zimbra, MSRC | Read the index and check eligible candidates. MSRC's expanded child records and saved child snapshots pass the same date guard. |
| AVD, CNVD, GOVCERT, HKCERT, Huawei SA, Palo Alto, Qianxin | Refresh recent listings and stop after a whole page older than the window. Known old publication/edit dates skip detail requests. No rotating archive scan. |

An older publication updated today is eligible. A changed title or summary with
old source dates is not. When listing metadata cannot establish an edit date,
the article may need to be fetched to verify it. Final records are checked again
before writing; missing/unparseable dates never default to today. Source limits
still apply: revisions outside a bounded feed or undisclosed changes on archived
listing pages are not guaranteed to be discovered.

## Limits and retries

* `--limit` defaults to 1,000 advisory checks per provider per invocation,
  including unchanged records and expanded MSRC children.
* Date checks that require fetching an article count toward `--limit`, even when
  the final record is outside the window. Known old listings skipped without
  fetching details do not consume the allowance.
* The allowance is available to current-window news and retries. Every invocation
  polls the newest source head before eligible pending work.
* `--batch-size` defaults to 5 and caps acknowledged write/checkpoint batches.
* `--max-runs-per-provider` defaults to 100 and bounds listing work per
  invocation. Cached pages can still be consumed without new listing requests.
* A non-blocking `data/catch-up.lock` prevents overlapping cron/manual invocations.
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
`up_to_date` means available work inside the current window was processed.
Older days are intentionally excluded, including after downtime.

Back up the affected program files before deploying, preserve the server's
`.env`, `mongodb.toml`, `scrapers.toml` and cron entry, then compare two runs:
recent updates should be written, and an unchanged second run should skip matching
records and retain or advance progress without resuming an archive. Verify records
independently in MongoDB.
If rolling back program files, retain the state collection and cache: the older
program ignores them and no news schema migration is required.
