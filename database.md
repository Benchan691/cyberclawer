# MongoDB Vulnerability Schema v2

The `vulnerabilities` database keeps one physical collection per provider and one
`<provider>_review` view. Existing document `_id` values and review-view names are
stable across migration.

## Stored document

```json
{
  "_id": "cve:2026-1000",
  "schema_version": 2,
  "code": "2026-1000",
  "title": "CVE-2026-1000",
  "severity": "High",
  "change_type": "new",
  "published_at": {"$date": "2026-07-01T00:00:00Z"},
  "updated_at": {"$date": "2026-07-02T00:00:00Z"},
  "observed_at": {"$date": "2026-07-02T01:00:00Z"},
  "source": {
    "url": "https://example.test/catalog",
    "detail_url": "https://example.test/CVE-2026-1000"
  },
  "details": {
    "descriptions": [],
    "references": [],
    "affected": []
  }
}
```

Non-CVE providers may also contain canonical, prefixed `cve_ids`. The `cve`
collection derives its identifier from `code` and therefore does not store a
redundant singleton array. `classification` is allowed only on CVE documents.

Optional values are omitted instead of being stored as empty strings, nulls,
empty arrays, or empty objects. Provider payloads live directly under `details`;
there is no `details.<provider>` wrapper.

Schema-v1 fields such as `type`, `status`, `cve_code`, `cve_codes`,
`related_cves`, `disclosure_date`, and `scraped_at` are not stored.

## Relationships and indexes

Related CVEs are resolved at read time from `cve_ids`; links are not materialized
inside advisory documents.

Each provider collection has:

- `observed_at` descending with `_id` descending
- partial `severity` plus `observed_at`
- partial `published_at`
- partial `cve_ids` for non-CVE providers
- partial `classification.status` for CVE

Strict MongoDB validators enforce the common envelope while leaving the
provider-specific `details` object open.

## Migration

Inspect the migration without writing:

```bash
vuln-scrape migrate-mongo --target-version 2 --dry-run
```

Apply during a maintenance window after pausing scraper, retention, and
classification writers:

```bash
vuln-scrape migrate-mongo --target-version 2
```

The command builds and validates `<provider>__v2` shadow collections, preserves
document IDs and CVE classifications, swaps validated collections into place,
recreates review views, and leaves timestamped `__backup_...` collections for
rollback. Backups are intentionally removed only by an explicit operator action
after the seven-day acceptance period.
