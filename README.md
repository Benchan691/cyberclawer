# Vulnerability Bulletin Scrapers

Terminal scrapers that ingest vulnerability bulletins into MongoDB. There is no web UI.

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
| `cnvd` | `cnvd` | Needs `.[cnvd]` |
| `cve` | `cve` | CVEProject cvelistV5 |
| `github_advisory` | `github_advisory` | Optional `GITHUB_TOKEN` |
| `hkcert` | `hkcert` | HTML |
| `hpe` | `hpe` | RSS + document API; HTTP-only; latest 50 Critical alerts |
| `huawei_sa` | `huawei_sa` | May need `HUAWEI_SA_X_CK` / `HUAWEI_SA_CSRF_TOKEN` |
| `juniper` | `juniper` | Coveo JSON API |
| `msrc` | `msrc` | Microsoft CVRF API |
| `nvd` | `nvd` | NVD CVE API 2.0 (`services.nvd.nist.gov`); optional `NVD_API_KEY`; details embedded in list response |
| `paloalto` | `paloalto` | HTML |
| `qianxin` | `qianxin` | JSON API |
| `splunk` | `splunk` | HTML |
| `zimbra` | `zimbra` | Zimbra Wiki release patches |

The HPE scraper reads the [HPE security bulletin RSS feed](https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed) for the latest 50 Critical alerts, then fetches each bulletin from the [HPE document API](https://support.hpe.com/hpesc/public/api/document). It uses ordinary HTTP requests only; the original `docDisplay` URL is retained in each bulletin detail.

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

Document shape, indexes, and migration: see [`database.md`](database.md).

## Usage

Run one scraper:

```bash
vuln-scrape run hkcert --limit 100
vuln-scrape run avd --limit 100
vuln-scrape run cnvd --limit 100
```

Catch up all (or configured) scrapers for today's Asia/Hong_Kong window:

```bash
vuln-scrape catch-up
vuln-scrape catch-up --limit 200 --days 7
```

Limit which scrapers `catch-up` runs in [`scrapers.toml`](scrapers.toml):

```toml
[scrapers.catch_up]
providers = ["hkcert", "cve", "cnvd"]
```

Other commands:

```bash
vuln-scrape unify-mongo --dry-run
vuln-scrape unify-mongo
```

`unify-mongo` builds and validates a shadow `news` collection before cutover.
The old physical source collections are renamed to timestamped backups. For a
deployment that used custom legacy collection names, repeat
`--source-collection <name>` for each one. Review views are no longer created.
