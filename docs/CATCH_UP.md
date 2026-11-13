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
provider starts with its current feed/index or the previous seven days.

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

## Source strategies

| Sources | Behavior |
| --- | --- |
| NVD | Modification-date windows, each at most 120 days; fixed offsets and window boundaries across resumes. |
| GitHub Advisory | `modified` ranges, `sort=updated`, and validated `Link` pagination URLs. |
| CVE | Delta batch `fetchTime` is the arrival cursor. An older advisory `dateUpdated` does not exclude a new arrival. |
| FortiGuard, HPE | Reconcile the complete current RSS feed; full details are fetched even for old dates. FortiGuard remains RSS-only. |
| Splunk, Zimbra, MSRC | Read the full index; process new/changed entries first and rotate through known details. MSRC child CVEs resume across limits. |
| AVD, CNVD, GOVCERT, HKCERT, Huawei SA, Palo Alto, Qianxin | Refresh recent listings and maintain an independent archive cursor. An old publication page can end the recent pass, but does not end archive checking. |

For sources without a modification filter, unchanged listing metadata can avoid
an immediate detail fetch during the recent pass. The archive pass fetches
details again, allowing revisions without changed listing dates to be detected.
These older revisions are found progressively, not necessarily in the next hour.

## Limits and recovery

* `--limit` defaults to 1,000 advisory checks per provider per invocation,
  including unchanged records and expanded MSRC children.
* Recent work and retries receive 80% of the allowance; history receives 20%.
  Unused capacity is borrowed. Every invocation polls the newest source head
  before older failures or backlog.
* `--batch-size` defaults to 5 and caps acknowledged write/checkpoint batches.
* `--max-runs-per-provider` defaults to 100 and bounds listing work per
  invocation. Cached pages can still be consumed without new listing requests.
* A non-blocking `data/catch-up.lock` prevents overlapping cron invocations.
  An overlapping invocation logs that it was skipped; it does not clear progress.

When CVE delta retention no longer covers a saved position, recovery pins an
official daily baseline archive, builds a local ID manifest, and fetches current
CVE records rather than writing stale archived bodies. Baseline processing is
resumable and shares the history allowance; hourly delta discovery continues.
Large baselines can therefore take many runs. Archive bytes are not extracted
as filesystem paths.
Current official `.zip.zip` baselines wrap an inner ZIP; both that format and
plain ZIP baselines are supported. Release SHA-256 digests are checked when
provided, and the selected asset is saved before downloading it.

RSS-only sources cannot recover advisories already dropped from the feed when
no history endpoint is configured. If visible dates suggest this coverage gap,
the summary reports it rather than claiming a complete historical recovery.

News upserts are idempotent. Comparison respects BSON UTC/millisecond storage,
and an older pinned observation cannot replace a subsequently observed record.
Failed details never replace full documents with listing summaries. Database
write failures retain retry references; one failure does not prevent other
updates being collected. Records disappearing from a listing are retained.

## Operation and rollback

Per-provider logs report checked/fetched counts, incremental status, history
status, pending windows/retries, and insert/update/skip/error counts. `partial`
and `error` are not caught-up states. Archive rotation is reported separately
from incremental completion.

Back up the affected program files before deploying, preserve the server's
`.env`, `mongodb.toml`, `scrapers.toml` and cron entry, then compare two runs:
the first should fill gaps, and an unchanged second run should skip matching
records and retain or advance progress. Verify records independently in MongoDB.
If rolling back program files, retain the state collection and cache: the older
program ignores them and no news schema migration is required.
