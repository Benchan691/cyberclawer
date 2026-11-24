# Palo Alto, MSRC, Huawei SA, and Zimbra RSS discovery

These four providers now discover records in official RSS feeds. Their keys,
shared `news` collection, source catalog, and hourly cron command stay the same.
There is no HTML-index or broad API-list fallback when a feed fails.

| Provider | Discovery feed | Detail processing |
| --- | --- | --- |
| `paloalto` | <https://security.paloaltonetworks.com/rss.xml> | Open each linked advisory; keep CVSS, severity, dates, product status, solutions, workarounds, grouped CVEs, and references. |
| `msrc` | <https://api.msrc.microsoft.com/update-guide/rss> | Look up the specific RSS CVE in `/cvrf/v3.0/Updates/CVE-…`, fetch its referenced CVRF document, and select only that CVE. |
| `huawei_sa` | <https://www.huawei.com/en/rss-feeds/psirt/rss> | Open the linked PSIRT advisory; collect full content, source dates, CVEs, fixes, references, and source CVSS scoring. |
| `zimbra` | <https://blog.zimbra.com/feed/> | Extract release-note links from RSS article content, then fetch the corresponding Wiki release notes. |

## Coverage and dates

The existing `--days 1` rule remains **today in Hong Kong**, using publication or
revision evidence from the source. Feed rebuild time and observation time never
make an old article current. Missing/unparseable dates do not default to today.
No archive scan or recovery of older missing records is enabled.

RSS is bounded: increasing `--limit` cannot discover records absent from the feed.
Feed failures are reported and leave work pending; they never trigger the previous
directory or broad API-list scraper. Disappearing items do not delete stored news.

Palo Alto currently exposes 25 feed entries. Discovery keeps both `CVE-…` and
`PAN-SA-…` identities. Detail pages remain authoritative for full advisory dates;
an older publication may qualify when the advisory page records a recent edit.

MSRC RSS timestamps represent CVE updates and are stored as `updated_at`, separate
from the CVRF publication date. Duplicate RSS entries are collapsed by CVE using
the latest timestamp/revision. Records retain `msrc:<year-number>` identities.
Full CVRF descriptions, products, severity, CVSS, remediation, and revision history
are retained. A monthly document is fetched once per client/run, including when
several RSS CVEs refer to it. Unrelated CVEs in that monthly document are not saved.
A missing CVE or failed CVRF request remains a failure; RSS text is not a full-detail
replacement. CVE-specific API lookups are detail enrichment, not alternative discovery.

Huawei's feed responded with 20 entries during verification on 24 November 2026,
but its newest feed date was 25 March 2026. Some linked advisories are older still.
**This feed does not demonstrate coverage of the current enterprise advisory list.**
The scraper warns when the newest feed timestamp is over 30 days old. Actual page
release/revision dates take precedence over feed timestamps, preventing old PSIRT
articles from being imported as current news. Existing enterprise records are not
deleted or rekeyed. Newly exposed legacy PSIRT links use their stable permalink
slug; enterprise links retain their existing opaque ID when present in RSS.

Huawei HTML pages expose CVSS base scores rather than the previous API's severity
field. When scores exist, their maximum maps to Critical (9+), High (7+), Medium
(4+), or Low. No score means no inferred severity. Full section content and source
scores remain available in the document.

Zimbra's separate `security-advisory-feed.php` reports revisions to the advisories
wiki page and supplies no release-version identifiers. The official blog RSS
instead links to the release notes our existing records represent. Generic blog
posts are ignored unless they link a supported release-note path. Installation
guides, external hosts, and duplicate release links are ignored. Where several
posts reference the same release, an announcement naming that version takes
priority over marketing references. A valid feed with no release links completes
with zero candidates.

Zimbra IDs remain versions such as `zimbra:10.1.21` and `zimbra:8.8.15/P47`.
Release dates come from the release notes; explicit Wiki last-edit metadata can
qualify a revision. A new marketing post linking an old release does not make that
release current. Full security fixes, other fixes, packages, installation and
repository links are kept. Fields previously available only in the release index
may be absent from newly collected records.

## Limits, progress, and recovery

MSRC uses the optional `list_content_type="html"` fetch path for RSS XML text,
while `content_type="json"` continues to select JSON detail handling. Providers
without this optional setting retain their existing fetch behavior.

The default limit remains 1,000 advisory checks per provider, with acknowledged
write/checkpoint batches controlled by `--batch-size`. `--max-runs-per-provider`
bounds source listing requests. Every feed is one list page; MSRC may issue
additional CVE-specific and monthly detail requests. Cached unfinished work resumes
under the same date guard, and MongoDB round trips do not cause unchanged records
to be rewritten. The existing process lock still prevents overlapping runs.

The first run after this change records discovery version `rss-v1` and retires
pending HTML/API listing snapshots belonging to the old discovery protocol.
Existing article retries retain their provenance, and stored historical records
remain untouched. No manual database migration or progress reset is required.

## Manual rollout only

No server deployment is performed for this change. For a later rollout:

1. Back up source, `scrapers.toml`, `mongodb.toml`, `.env`, cron, and existing progress.
2. Review and update the existing `/home/cpcnet/cyberclawer` checkout, preserving local
   configuration. No new dependencies, webserver rebuild, or database migration is needed.
3. Keep the existing hourly `vuln-scrape catch-up --days 1` cron entry. Existing
   `providers = ["all"]` or explicit selections of these provider keys continue to work.
4. Run only the selected provider twice, for example:

   ```bash
   ./.venv/bin/vuln-scrape run paloalto --days 1 --limit 1000
   ./.venv/bin/vuln-scrape run paloalto --days 1 --limit 1000
   ```

5. Check completion, pending retries, source coverage warnings, and MongoDB errors
   separately. Inspect source IDs, full details, and source timestamps in `news`.
   Unchanged runs should insert/replace nothing. Zero current-window records is valid;
   do not widen the date window merely to create inserts.
6. Preserve subscriptions, queued emails, delivery receipts, and newsletter display
   records. Do not send test newsletters to real recipients for verification.

Rollback restores the previous scraper code and its discovery settings. Preserve
existing configuration and news records; do not delete data to roll back code.

## Verification

Tests cover valid/empty/malformed feeds, untrusted links, duplicate revisions,
stable IDs, full-detail validation, current date boundaries, backdated references,
RSS-only failure behavior, MSRC selection/cache/limits, failed detail recovery,
old discovery cursors, and unchanged MongoDB writes. Live checks validate the
official feeds and representative full records without writing production data.

On 24 November 2026, 560 automated tests passed with two existing skips. The two
unrelated classifier test modules remain excluded because this checkout does not
contain `vendor_product_classifier`. All four live feed/detail paths produced
valid schema v2 records. Separate local MongoDB checks confirmed that a second
unchanged run makes zero inserts or replacements for each converted provider.
