# Splunk scraper implementation

Cyberclawer discovers Splunk security advisories through RSS and fetches the
linked HTML pages for full content, affected versions, CVEs, and edit dates.

| Setting | Value |
| --- | --- |
| Provider | `splunk` |
| Discovery feed | [Splunk Security Announcements RSS](https://advisory.splunk.com/feed.xml) |
| Advisory URL | `https://advisory.splunk.com/advisories/<SVD-ID>` |
| Stored source link | `https://advisory.splunk.com/advisories` in `source.url` |
| Collection | Shared `news` collection, or the configured shared collection |
| Document identity | `splunk:<SVD-ID>`, for example `splunk:SVD-2026-1010` |

## Discovery and detail extraction

1. Read `feed.xml` as a single RSS listing. Accept HTTPS links on
   `advisory.splunk.com` with an `/advisories/SVD-…` path. The link supplies
   the normalized uppercase SVD ID and duplicate IDs are skipped.
2. Remove the matching SVD prefix from the title. Convert the RSS description
   to plain text and parse `pubDate` as a calendar date. The title and summary
   can supply CVE IDs.
3. Fetch the full advisory page. Extract the article text, description,
   remediation, mitigations, changelog, CVE details, references, and available
   product and package tables.
4. Use the page's published date, with the RSS date as a fallback. Read the
   page's `Last Updated` or `Last Update` field for the edit date. The RSS
   summary and CVEs fill missing details. Use the advisory's severity from
   its CVSS header, or the highest recognized severity in its CVE and package
   tables when the header has no rating.

A grouped advisory produces one document containing all its CVE IDs and a
`details.cve_details` section when Splunk provides one. A valid empty RSS
channel completes discovery. Invalid XML, a missing channel, and a nonempty
feed without usable Splunk links are reported as list failures.

## Catch-up and coverage

- Both `run splunk` and `catch-up` use the shared publication and edit date
  window. `--days 1` covers today in Hong Kong time. `--days 2` also covers
  yesterday.
- The feed provides publication dates. Catch-up checks the advisory pages for
  edits, even when an RSS entry has the same title, summary, and publication
  date. An older advisory qualifies when its edit date is in the window.
- `--limit` counts advisory checks, including page fetches that establish that
  an advisory is outside the window. Catch-up saves progress and retries
  eligible failed fetches or writes. A failed detail request leaves any stored
  full advisory available.
- Discovery covers the items Splunk currently publishes in the feed. The
  live feed contained 30 items during verification. Existing records stay
  stored when they leave the feed and later revisions to those records can be
  missed. Fields that Splunk supplies only in its HTML archive can be absent
  from refreshed records.

## Stored MongoDB fields

The records use schema v2. The scraper's intermediate representation nests
the provider fields under `details.splunk`. In MongoDB, the provider fields
are directly under `details`.

| Field | Type | Meaning |
| --- | --- | --- |
| `_id` | string | Stable `splunk:<SVD-ID>` key |
| `schema_version` | integer | `2` |
| `code` | string | SVD ID |
| `title` | string | Cleaned RSS title |
| `observed_at` | BSON date | Scrape time for the stored version |
| `published_at` | BSON date | Publication time, when available |
| `updated_at` | BSON date | Edit time. The shared schema can use the publication time as a fallback. |
| `severity` | string | Recognized rating such as `High` or `Critical`, when available |
| `cve_ids` | string array | Unique uppercase CVE IDs, when available |
| `source` | object | `provider`, `url` for the archive link, and `detail_url` for the advisory |
| `details` | object | Text and structured data extracted from the advisory |

| Optional keys in `details` | Content |
| --- | --- |
| `content`, `description`, `details`, `cve_details` | Plain text for the article and its extracted sections |
| `solution`, `mitigations`, `changelog`, `credit` | Remediation, workarounds, revision history, and acknowledgments |
| `cvss_score`, `cvss_vector`, `cwe`, `severity_summary`, `severity_detail` | Rating and weakness information supplied by the advisory |
| `affected_products`, `affected_versions`, `fixed_versions`, `all_affected_versions`, `affected_components`, `oss`, `bug_ids` | Additional source metadata when available |
| `product_status` | Array of rows with keys such as `product`, `base_version`, `affected_version`, and `fix_version` |
| `packages` | Array of rows with keys such as `package`, `remediation`, `cve`, and `severity` |
| `description_tables`, `tables` | Array of objects with `headers` and `rows` |
| `reference_links`, `raw_fields` | Array of links and a map of parsed source labels |

MongoDB omits empty optional fields. Date values in the example are ISO 8601
strings for readability. MongoDB stores the values as dates.

```json
{
  "_id": "splunk:SVD-2026-1010",
  "schema_version": 2,
  "code": "SVD-2026-1010",
  "title": "Example Splunk advisory",
  "observed_at": "2026-10-22T03:00:00Z",
  "published_at": "2026-10-20T16:00:00Z",
  "updated_at": "2026-10-21T16:00:00Z",
  "severity": "High",
  "cve_ids": ["CVE-2026-12345", "CVE-2026-12346"],
  "source": {
    "provider": "splunk",
    "url": "https://advisory.splunk.com/advisories",
    "detail_url": "https://advisory.splunk.com/advisories/SVD-2026-1010"
  },
  "details": {
    "content": "Example advisory text.\nUpgrade to the fixed version.",
    "solution": "Upgrade to version 8.7.0.",
    "product_status": [
      {
        "product": "Example Splunk product",
        "base_version": "8.7",
        "affected_version": "Below 8.7.0",
        "fix_version": "8.7.0"
      }
    ],
    "reference_links": ["https://advisory.splunk.com/advisories/SVD-2026-1010"]
  }
}
```

For another project, filter by `source.provider = "splunk"` and link users to
`source.detail_url`. Use the top-level `cve_ids` for CVE filters and
`details.content` for the article body.

## Run and verify

```sh
vuln-scrape run splunk --days 2 --limit 30
python -m pytest -q --import-mode=importlib tests/scrapers/splunk
```

The live check parsed all 30 feed entries, fetched four full advisory pages,
and passed the resulting records through the MongoDB write path using a test
double. The [catch-up regression test](../tests/scrapers/splunk/test_splunk_provider.py)
verifies that a detail-only edit updates the same stored SVD document.

The main implementation is in the [provider](../vuln_scraper/scrapers/splunk/provider.py),
[RSS parser](../vuln_scraper/scrapers/splunk/parsers/list.py), and
[detail parser](../vuln_scraper/scrapers/splunk/parsers/detail.py).
