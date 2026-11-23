# Vulnerability Bulletin Scrapers

Terminal scrapers that ingest vulnerability bulletins into MongoDB. There is no web UI.

詳細開發與維運說明（繁體中文）：[Cyberclawer 開發與維運手冊](docs/DEVELOPMENT.zh-Hant.md)。

## Start guide

Requires Python 3.11+.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional extras:

```bash
pip install -e '.[avd]'           # Aliyun AVD (sigchl via quickjs)
pip install -e '.[cnvd]'          # CNVD gate (quickjs + captcha OCR)
```

Point MongoDB at your cluster via `mongodb.toml` or env vars (`MONGO_URI`, `MONGO_DB`).

## Scrapers

Providers are plugins: each lives in its own package under `vuln_scraper/scrapers/<key>/`
(with a `provider.py` that exposes a keyed provider class) and is discovered automatically —
adding a scraper means dropping in a directory, removing one means deleting it.

| Key | `source.provider` | Notes |
| --- | --- | --- |
| `avd` | `avd` | Needs `.[avd]`; sigchl solved via quickjs |
| `bleepingcomputer` | `bleepingcomputer` | Main news RSS with article summaries, bylines, and categories |
| `cnvd` | `cnvd` | Needs `.[cnvd]` |
| `cve` | `cve` | CVEProject cvelistV5 |
| `fortiguard` | `fortiguard` | PSIRT RSS feed + full advisory pages; optional CSAF enrichment |
| `github_advisory` | `github_advisory` | Optional `GITHUB_TOKEN` |
| `govcert` | `govcert` | GOVCERT.HK English RSS + full alert pages |
| `hkcert` | `hkcert` | Security bulletin RSS + full bulletin pages |
| `hpe` | `hpe` | RSS + document API; HTTP-only; latest 50 Critical alerts |
| `huawei_sa` | `huawei_sa` | May need `HUAWEI_SA_X_CK` / `HUAWEI_SA_CSRF_TOKEN` |
| `msrc` | `msrc` | Microsoft CVRF API |
| `nvd` | `nvd` | NVD CVE API 2.0 (`services.nvd.nist.gov`); optional `NVD_API_KEY`; details embedded in list response |
| `paloalto` | `paloalto` | HTML |
| `qianxin` | `qianxin` | JSON API |
| `splunk` | `splunk` | RSS feed + full advisory pages with grouped CVEs |
| `the_hacker_news` | `the_hacker_news` | Full articles when available, with RSS summaries when article access is denied |
| `wiz` | `wiz` | Cloud Threat Landscape RSS + full incident pages; permanent feed GUID identities |
| `zimbra` | `zimbra` | Zimbra Wiki release patches |

The BleepingComputer scraper imports all categories from the [main news RSS
feed](https://www.bleepingcomputer.com/feed/). Each record stores the feed
summary, byline, categories, and any CVEs named in the title or summary. The
canonical article URL is stored in `source.detail_url`. The `--days` window
uses article publication times and covers articles still present in the feed.
The `providers = ["all"]` setting includes BleepingComputer automatically.
See the [BleepingComputer implementation guide](docs/BLEEPINGCOMPUTER.md).

The HPE scraper reads the [HPE security bulletin RSS feed](https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed) for the latest 50 Critical alerts, then fetches each bulletin from the [HPE document API](https://support.hpe.com/hpesc/public/api/document). It uses ordinary HTTP requests only; the original `docDisplay` URL is retained in each bulletin detail.

The Splunk scraper discovers advisories through the [Splunk Security Announcements RSS feed](https://advisory.splunk.com/feed.xml).
It opens each selected `/advisories/SVD-*` page for the full text, tables,
grouped CVEs, and edit date. The existing `--days` window applies to both
new publications and revisions. Discovery is limited to advisories in the
current feed, and `--limit` counts advisory checks. Fields published only in
the archive can be absent from newly fetched records.

See the [Splunk implementation and schema](docs/splunk.md).

The FortiGuard scraper uses [Fortinet's PSIRT RSS feed](https://filestore.fortinet.com/fortiguard/rss/ir.xml)
as its only advisory list source. The feed covers the latest 50 advisories and
has no historical pagination. The scraper then opens each `/psirt/FG-IR-*` article, such as
`/psirt/FG-IR-26-182`. It saves the full advisory in `details.content`, including
workarounds, references, and version tables, plus severity, CVEs, publication and
update dates, and affected product/solution rows. The shared `news` collection
identifies these documents with `source.provider = "fortiguard"`.
Feed failures after retries and advisory page failures are reported normally;
there is no fallback to the PSIRT directory.

During `run` and `catch-up`, FortiGuard reads the current feed and applies the
same publication/update window as every other source. The default `--days 1`
accepts only articles published or updated today in Hong Kong time. Article
pages may be needed to verify edit dates missing from RSS. Missing eligible
records are inserted, changed records are overwritten, and unchanged records
are skipped. A feed rebuild time is not an advisory's publication or revision
date. Records no longer present in the feed are retained.
Content comparison accounts for MongoDB's UTC timestamp representation and
millisecond precision so unchanged records are not rewritten on each run.

The GOVCERT scraper discovers English alerts through the [GOVCERT.HK security alerts RSS feed](https://www.govcert.gov.hk/en/rss_security_alerts.xml).
It opens linked pages for the full text, affected systems, impact,
recommendations, CVE IDs, tags, references, and tables. The page's
`Last update on` date lets `run` and `catch-up` include revisions within
the `--days` window even when the RSS publication date is older. Discovery
covers the current feed. High-threat alerts are `Critical` and standard
alerts are `Medium`.

The HKCERT scraper discovers English bulletins through the [HKCERT security bulletin RSS feed](https://www.hkcert.org/getrss/security-bulletin).
It opens each selected bulletin to collect CVEs, impact, affected systems,
solutions, and product tables. A page's `Last Update Date` can qualify an
older bulletin for the `--days` window while it remains in the feed.
Discovery covers the current feed. Listing badges from the HTML archive are
unavailable in RSS, so newly fetched records can omit `change_type`.

The Wiz scraper reads the [Cloud Threat Landscape RSS feed](https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml)
and fetches each linked incident page for its full text, actors, techniques,
targeted technologies, references, CVEs, and publication/edit dates. Campaigns,
incidents, and research entries are included. Records use the feed's permanent
GUID as their identity and `source.provider = "wiz"` in the shared `news`
collection. Permanent ID links resolve renamed pages even when a feed slug is
outdated. Historical entries with no prose retain their structured metadata.
Both commands accept only records published or edited within `--days`, up to
`--limit`. Wiz exposes edit dates on article pages rather than in RSS, so old
feed entries may require a detail-date check; old unchanged articles are not saved.
The feed has no pagination; records that leave it are retained. The existing
`providers = ["all"]` setting includes Wiz automatically.

Schema and implementation handoff for other applications: [Wiz schema](docs/WIZ_SCHEMA.md).

The Hacker News scraper uses [its RSS feed](https://feeds.feedburner.com/TheHackersNews)
for discovery, then opens the linked articles for full text, author, categories,
references, CVEs when present, and publication/revision dates. If article access is
denied, the rest of that run uses RSS dates and summaries. `providers = ["all"]` includes
`the_hacker_news` automatically; explicitly selected providers must include that key.
The current `--days` news-date window applies, so `--days 1` collects only articles
published or revised today in Hong Kong time. General news does not receive an
invented severity or CVE. Stable IDs use the article's year, month, and permalink
slug, ignoring tracking parameters. Records remain in `news` after leaving the feed.
See [The Hacker News schema and operations](docs/THE_HACKER_NEWS.md).
For a later server update, use [The Hacker News deployment guide](docs/THE_HACKER_NEWS_DEPLOYMENT.md).

## MongoDB layout

All scrapers write to one physical `news` collection. Every document records
its origin in `source.provider`, for example `cve`, `hkcert`, or `hpe`.
Configure the shared collection in [`mongodb.toml`](mongodb.toml):

```toml
[mongodb]
uri = "mongodb://localhost:27017"
database = "vulnerabilities"
collection = "news"
conflict = "overwrite"
```

Precedence: env vars (`MONGO_URI`, `MONGO_DB`, `MONGO_COLLECTION`) >
`mongodb.toml` > defaults. Provider-specific collection tables from older
releases are ignored for runtime writes.

The configured catch-up provider list is also published atomically to the
`source_catalog` collection in the same database. The portal reads this list
to populate provider filters, including providers that have not published a
document yet. Sync the catalog without running scrapers with:

```bash
vuln-scrape sync-source-catalog
```

Or run the standalone updater using this checkout's `.env`, `mongodb.toml`,
and `scrapers.toml` settings:

```bash
python update_source_collection.py --dry-run  # Preview; no database connection
python update_source_collection.py            # Upsert source_catalog/_id=active
```

The updater publishes the configured provider list, including `fortiguard`,
without scraping or modifying `news` documents.

Document shape, indexes, and migration: see [`database.md`](database.md).

## Usage

Run one scraper (today's publications and updates by default):

```bash
vuln-scrape run hkcert --limit 100
vuln-scrape run avd --limit 100
vuln-scrape run cnvd --limit 100
vuln-scrape run splunk --limit 1000
vuln-scrape run govcert --limit 10
vuln-scrape run fortiguard --limit 20
vuln-scrape run wiz --limit 20
vuln-scrape run bleepingcomputer --days 2
```

Resume all (or configured) scrapers from their saved sync progress:

```bash
vuln-scrape catch-up
vuln-scrape catch-up --limit 200 --days 1
```

`--days 1` includes source publication or update dates from midnight today in
Hong Kong time. This applies to every provider in both `run` and `catch-up`.
`--days 2` explicitly includes yesterday and today. Old saved positions cannot
widen the requested window; expired queued pages and retries are retired.
New and changed eligible advisories are inserted or updated; matching records
are skipped. Details without a verifiable publication or edit date are not saved.
Unfinished eligible work resumes on later runs. Existing historical news records
are retained; there is no historical recovery or rotating archive scan.
`--limit` counts advisories checked, `--batch-size` controls write/checkpoint
batches, and `--max-runs-per-provider` caps listing work. Overlapping scheduled
runs, including manual `run` invocations, are skipped using a process lock. See [resumable catch-up](docs/CATCH_UP.md)
for source strategies, state storage and rollout.

Transient HTTP errors honor `Retry-After` and use the retry/backoff settings in
`scrapers.toml`. CNVD and NVD use longer backoff for gateway/service failures.
Retries remain bounded; an unavailable source is reported as a failure.

Keep `data/checkpoint.json` and `data/sync-cache/` between runs. Saved catch-up
positions and retry references live in MongoDB's `news_sync_state` collection;
legacy failed requests are imported automatically. Failed detail requests from
every source are retried while their source dates remain in the requested window.
Failed fetches do not overwrite existing records with list summaries. NVD
keeps eligible request windows fixed across pagination; expired windows are
discarded when the Hong Kong calendar boundary advances.
NVD pagination uses the requested page size, including when the final response
contains fewer records. Empty results are accepted only when the response's
pagination metadata confirms that the result set is exhausted; unexpected empty
pages still produce failure alerts.

Limit which scrapers `catch-up` runs in [`scrapers.toml`](scrapers.toml):

```toml
[scrapers.catch_up]
providers = ["hkcert", "cve", "cnvd"]
```

## Failure email alerts

When any URL fetch fails during a run (list page, detail page, or a run that
stops with an error), the scraper sends a CSS-styled HTML report with the failed
items, errors, and URLs. An uncaught run crash also sends an alert. SMTP relay
settings are read from the webserver `.env` file (`SMTP_HOST`, `SMTP_PORT`,
`SMTP_USERNAME`, `SMTP_FROM`, `SMTP_USE_TLS`, `SMTP_USE_SSL`).

Recipients and alerting behaviour are configured in the `[scrapers.email]`
table of [`scrapers.toml`](scrapers.toml):

```toml
[scrapers.email]
enabled = true
to = ["ben.chan@citictel-cpc.com"]
cc = []
bcc = []
repeat_hours = 24
env_file = "/home/cpcnet/webserver-rust-zimbra-candidate/.env"
```

A failure is only re-reported after `repeat_hours` has elapsed, so chronic
failures do not email on every hourly run; new failures always trigger an
email. Sent state is kept in `data/email-alert-state.json`. Alert sending
never interrupts a scrape run - delivery problems are logged and retried on
the next run.

Other commands:

```bash
vuln-scrape unify-mongo --dry-run
vuln-scrape unify-mongo
```

`unify-mongo` builds and validates a shadow `news` collection before cutover.
The old physical source collections are renamed to timestamped backups. For a
deployment that used custom legacy collection names, repeat
`--source-collection <name>` for each one. Review views are no longer created.
