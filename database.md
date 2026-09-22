# MongoDB Unified News Schema v2

The `vulnerabilities` database uses one physical collection, `news`, for every
scraper. No `<provider>_review` views are created. Consumers filter the common
collection with `source.provider` and render the normalized document directly.

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
    "provider": "cve",
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

`source.provider` is required and must be a registered scraper key. `_id`
remains provider-prefixed, so identities stay stable when the old collections
are merged.

Non-CVE providers may contain canonical, prefixed `cve_ids`. CVE documents
derive their identifier from `code` and may contain `classification`.
Classification is rejected on every other provider by application validation.

Optional values are omitted instead of storing empty strings, nulls, empty
arrays, or empty objects. Provider payloads live directly under `details`; there
is no `details.<provider>` wrapper. Schema-v1 fields such as `type`, `status`,
`cve_code`, `cve_codes`, `related_cves`, `disclosure_date`, and `scraped_at` are
not stored.

## Indexes

The unified collection has:

- `observed_at` descending with `_id` descending
- `source.provider` plus `observed_at` descending
- `source.provider`, `severity`, and `observed_at` descending
- partial `severity` plus `observed_at`
- partial `published_at`
- partial `cve_ids`
- partial `classification.status`

A strict MongoDB validator enforces the common envelope and required provider
discriminator while leaving the provider-specific `details` object open.

## Shadow-first migration

Pause scraper and classifier writers, then inspect the migration:

```bash
vuln-scrape unify-mongo --dry-run
```

If an older deployment used custom collection names, list them explicitly:

```bash
vuln-scrape unify-mongo --dry-run \
  --source-collection legacy_cve \
  --source-collection vendor_alerts
```

Apply during the maintenance window:

```bash
vuln-scrape unify-mongo
```

The command converts and validates every document in a shadow collection,
checks count and ID parity, removes only known legacy review views, and then
renames the validated shadow into place. Every old physical source collection
is retained as `<name>__backup_<timestamp>`. A failed cutover restores all
renamed physical collections.

After at least seven days of acceptance, backups can be reviewed and removed by
an explicit operator action:

```bash
vuln-scrape cleanup-mongo-backups --dry-run --older-than-days 7
vuln-scrape cleanup-mongo-backups --older-than-days 7
```
