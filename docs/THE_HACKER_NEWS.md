# The Hacker News

Provider key: `the_hacker_news`. Discovery URL:
<https://feeds.feedburner.com/TheHackersNews>. Article discovery is RSS-only.
The bounded feed is checked each run; it has no historical pagination or fallback.

```bash
vuln-scrape run the_hacker_news --days 1 --limit 1000
vuln-scrape catch-up --days 1
vuln-scrape sync-source-catalog
```

`catch-up` includes this provider when `scrapers.toml` selects `all`. Existing cron
entries need no change. Both commands use the shared Hong Kong calendar-day window:
`--days 1` is today, based on source publication or revision dates. Older feed
entries may need an article fetch to check their edit dates. Limits, retry/checkpoint batches,
the catch-up process lock, and unchanged-content comparison use the shared engine.

Documents use schema v2 in `vulnerabilities.news`:

| Field | Meaning |
| --- | --- |
| `_id` | `the_hacker_news:YYYY-MM-permalink-slug` |
| `code` | `YYYY-MM-permalink-slug`; independent of title, CVEs, and tracking parameters |
| `source.provider` | `the_hacker_news` |
| `source.url` | `https://thehackernews.com/` |
| `source.detail_url` | Canonical HTTPS permalink used for the article fetch |
| `published_at`, `updated_at` | UTC BSON dates from the article; RSS publication date fills a missing publication date |
| `observed_at` | Time collected; excluded from unchanged-content comparison |
| `cve_ids` | Actual CVE references, if present; articles without CVEs are valid |
| `details.content` | Full plain text, with paragraph/list boundaries |
| `details.summary`, `author`, `categories`, `reference_links` | Source metadata and HTTP(S) references |
| `details.content_source` | `rss` when only the feed summary is available |

An HTTP 403 or access challenge switches the run to RSS summaries. Cyberclawer
uses the item's publication date to determine eligibility and keeps any full
article already stored. A later run can upgrade an eligible RSS record to the
full article. Malformed feeds, missing article bodies, and transient network
failures remain retryable. The CLI reports the number of items outside the date
window and the number of pending retries.

The shared MongoDB source catalog makes this provider available to downstream
source selectors. News articles may include CVEs from the source.
