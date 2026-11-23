# BleepingComputer scraper implementation

Cyberclawer registers this source as `bleepingcomputer`. One RSS request supplies article summaries and metadata for all categories present in the feed. [BleepingComputer main news RSS](https://www.bleepingcomputer.com/feed/)

## RSS ingestion

1. Request the RSS feed with an XML `Accept` header and the `Cyberclawer RSS Reader` user agent.
2. Read each item's title, publication time, and HTTPS article link under `www.bleepingcomputer.com/news/`. The parser tries `link` first and uses `guid` when it contains a usable article URL. It derives the article key from `<category>/<slug>`, dropping query strings, fragments, and trailing slashes.
3. Convert the RSS description to plain text. Read the author from `dc:creator` and keep distinct category labels in feed order. Extract unique uppercase CVE IDs from the title and summary.
4. Keep one record per article path. A single record can contain multiple CVEs.

The parser skips items with missing titles, invalid publication dates, or unusable links. An empty RSS channel completes discovery. Invalid XML, a missing channel, and a nonempty channel with no usable items are reported as feed errors.

## MongoDB document schema

Records use schema v2 in the configured shared collection, normally `news`. Provider fields sit directly under `details`. Optional fields appear when the feed supplies a value.

| Field | Type | Stored value |
| --- | --- | --- |
| `_id` | String | `bleepingcomputer:<category>/<slug>` |
| `schema_version` | Integer | `2` |
| `code` | String | `<category>/<slug>` from the article URL |
| `title` | String | RSS title with normalized whitespace |
| `published_at` | BSON date | Item `pubDate`, converted to UTC |
| `updated_at` | BSON date | The same value as `published_at`. The shared schema uses the publication time as the fallback for this feed. |
| `observed_at` | BSON date | When Cyberclawer fetched the stored version. Unchanged articles retain their previous observation time. |
| `cve_ids` | Optional string array | CVEs mentioned in the RSS title or summary |
| `source.provider` | String | `bleepingcomputer` |
| `source.url` | String | `https://www.bleepingcomputer.com/` |
| `source.detail_url` | String | Canonical article URL for opening the source |
| `details.summary` | Optional string | Plain-text excerpt from the feed |
| `details.author` | Optional string | Publisher's byline |
| `details.categories` | Optional string array | Category labels as supplied by the feed |

This example uses a synthetic feed item. The `$date` values show BSON dates in MongoDB Extended JSON.

```json
{
  "_id": "bleepingcomputer:security/example-vendor-patches",
  "schema_version": 2,
  "code": "security/example-vendor-patches",
  "title": "Example vendor patches CVE-2026-12345",
  "published_at": { "$date": "2026-11-13T01:15:00Z" },
  "updated_at": { "$date": "2026-11-13T01:15:00Z" },
  "observed_at": { "$date": "2026-11-13T09:30:00Z" },
  "cve_ids": ["CVE-2026-12345", "CVE-2026-23456"],
  "source": {
    "provider": "bleepingcomputer",
    "url": "https://www.bleepingcomputer.com/",
    "detail_url": "https://www.bleepingcomputer.com/news/security/example-vendor-patches/"
  },
  "details": {
    "summary": "The update addresses cve-2026-12345 and CVE-2026-23456.",
    "author": "Test Reporter",
    "categories": ["Security", "Software"]
  }
}
```

To read BleepingComputer articles from the shared collection in publication order, query MongoDB by provider.

```javascript
db.news.find({ "source.provider": "bleepingcomputer" }).sort({ published_at: -1 })
```

## Date window and retries

Both `run` and `catch-up` use the item's publication timestamp and the Hong Kong calendar day. `--days 1` covers today from local midnight. `--days 2` also covers yesterday. A feed timestamp of `2026-11-12 20:15 -05:00` falls on November 13 at 09:15 in Hong Kong.

New discovery is limited to items present in the RSS feed. Within the selected publication window, a changed feed item can update its existing record. Stored articles remain in MongoDB after the feed drops them.

Catch-up saves progress in the shared sync state collection, normally `news_sync_state`. Failed database writes retain the RSS excerpt, metadata, and original observation time, so an eligible article can be retried after it leaves the feed or the local snapshot is lost. [Catch-up behavior](CATCH_UP.md)

## Run and verify

Run BleepingComputer or the configured catch-up sources for today. A valid feed
can return zero records after Hong Kong midnight. `outside_window` counts feed
items excluded by the date filter.

```bash
vuln-scrape run bleepingcomputer --days 1
vuln-scrape catch-up --days 1
```

Catch-up includes BleepingComputer when `[scrapers.catch_up]` selects `providers = ["all"]`. With an explicit provider list, include `"bleepingcomputer"`. To preview the provider list used by downstream source selectors, run `vuln-scrape sync-source-catalog --dry-run`.

Run the source tests from the repository root. They cover RSS parsing, duplicate links, the Hong Kong date boundary, stored fields, and retry after feed and snapshot changes.

```bash
python -m pytest -q --import-mode=importlib tests/scrapers/bleepingcomputer
```

The provider defines requests, article URLs, and schema registration. [provider.py](../vuln_scraper/scrapers/bleepingcomputer/provider.py)

The parser reads the RSS channel and normalizes each article's fields. [list.py](../vuln_scraper/scrapers/bleepingcomputer/parsers/list.py), [detail.py](../vuln_scraper/scrapers/bleepingcomputer/parsers/detail.py)
