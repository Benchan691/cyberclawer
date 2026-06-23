# MongoDB Layout

## Overview

The scraper writes one MongoDB database from `mongodb.toml` (`vulnerabilities` by default). Each scraper owns one collection. Document `_id` is `{type}:{code}`, for example `cve:2026-1000`.

## Collections

| Scraper | Collection |
| --- | --- |
| avd | avd |
| cisco | cisco |
| cnnvd | cnnvd |
| cnvd | cnvd |
| cve | cve |
| github_advisory | github_advisory |
| govcert | govcert |
| hikvision | hikvision |
| hkcert | hkcert |
| huawei_sa | huawei_sa |
| infosec | infosec |
| juniper | juniper |
| msrc | msrc |
| paloalto | paloalto |
| qianxin | qianxin |
| ransomwarelive | ransomwarelive |
| splunk | splunk |
| zeroday | zeroday |

## Common Document

| Field | Notes |
| --- | --- |
| `_id` | `{type}:{code}` |
| `type` | Provider key |
| `code` | Provider-native ID |
| `title` | Display title |
| `cve_codes` | Normalized bare CVE codes, e.g. `2026-1000` |
| `disclosure_date`, `published_time`, `updated_time` | Source and normalized timestamps |
| `severity`, `status` | Normalized severity and source status |
| `details` | Provider-specific detail block |
| `source` | Provider URL metadata |
| `scraped_at` | Scrape run timestamp |
| `related_cves` | Links to matching `cve` collection documents |

Removed from stored documents: `cve_code`, `related_cve_ids`, `vuln_type`, `details.*.raw`, `details.*.raw_tables`, `details.*.raw_sections`, and non-CNVD `raw_fields`.

## Details

Provider detail fields stay under `details.<provider>`. CVE details keep parsed CVE v5 fields such as `source_identifier`, `last_modified`, `descriptions`, `metrics`, `weaknesses`, `references`, `configurations`, `affected`, and `cve_tags`.

For CVE records, `cve_id`, `title`, `published`, `vuln_status`, `affected_products`, and `raw` are removed because top-level fields or parsed `affected`/`configurations` cover them. UIs derive affected product labels at read time.

CNVD keeps `details.cnvd.raw_fields`; it is a parse source, not just a duplicate API blob.

## Classification

Only the `cve` collection is classified. The scraper preserves `classification` during overwrite; classifier workers own updates.

`method` is optional on classified records: `dictionary` (local CPE CSV lookup) or `zero_shot` (embedding match).

Classified:

```json
{
  "status": "classified",
  "vendor": "Cisco",
  "product": "IOS XE",
  "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
  "confidence": 0.91,
  "method": "dictionary",
  "dictionary_version": "a1b2c3d4",
  "classifier_version": 2,
  "updated_at": "2026-06-23T12:00:00+00:00"
}
```

Unclassified:

```json
{
  "status": "unclassified",
  "reason": "confidence below threshold",
  "confidence": 0.42,
  "candidate": {
    "vendor": "Cisco",
    "product": "IOS XE",
    "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*"
  },
  "dictionary_version": "a1b2c3d4",
  "classifier_version": 2,
  "updated_at": "2026-06-23T12:00:00+00:00"
}
```

Failed:

```json
{
  "status": "failed",
  "error": "message",
  "attempts": 3,
  "classifier_version": 2,
  "updated_at": "2026-06-23T12:00:00+00:00"
}
```

## Links And Indexes

`related_cves` links advisories to `cve` records by matching `cve_codes`. New indexes are `type/code` unique, `cve_codes`, `related_cves.cve_code`, `disclosure_date`, `published_time`, `updated_time`, `status`, and `severity`.

## Migration

Run dry first:

```bash
vuln-scrape migrate-mongo --dry-run
vuln-scrape migrate-mongo --database vulnerabilities
```

The migration is idempotent: it unsets legacy fields, normalizes `cve_codes`, removes non-CVE classification, and converts CVE classification v1 fields to v2.

To fix wrong CVE vendor/product classifications after a dictionary change, run:

```bash
vuln-scrape reclassify-cve --dry-run
vuln-scrape reclassify-cve --database vulnerabilities
```
