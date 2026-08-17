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
pip install -e '.[browser]'       # Playwright (Hikvision; AVD fallback)
pip install -e '.[cnvd]'          # CNVD gate (quickjs + captcha OCR)
pip install -e '.[browser,avd]'   # common combo
```

Point MongoDB at your cluster via `mongodb.toml` or env vars (`MONGO_URI`, `MONGO_DB`).

## Scrapers

| Key | Collection | Notes |
| --- | --- | --- |
| `avd` | `avd` | Needs `.[avd]`; browser optional |
| `cisco` | `cisco` | Needs `CISCO_OPENVULN_TOKEN` or client id/secret |
| `cnnvd` | `cnnvd` | JSON API |
| `cnvd` | `cnvd` | Needs `.[cnvd]` |
| `cve` | `cve` | CVEProject cvelistV5 |
| `fortiguard` | `fortiguard` | Fortinet PSIRT HTML; downloads CSAF JSON from each advisory |
| `github_advisory` | `github_advisory` | Optional `GITHUB_TOKEN` |
| `govcert` | `govcert` | HTML |
| `hikvision` | `hikvision` | Needs `.[browser]` |
| `hkcert` | `hkcert` | HTML |
| `huawei_sa` | `huawei_sa` | May need `HUAWEI_SA_X_CK` / `HUAWEI_SA_CSRF_TOKEN` |
| `infosec` | `infosec` | HTML |
| `juniper` | `juniper` | Coveo JSON API |
| `msrc` | `msrc` | Microsoft CVRF API |
| `paloalto` | `paloalto` | HTML |
| `qianxin` | `qianxin` | JSON API |
| `ransomwarelive` | `ransomwarelive` | Needs `RANSOMWARE_LIVE_API_KEY` or `RANSOM_API_KEY` |
| `splunk` | `splunk` | HTML |
| `zeroday` | `zeroday` | HTML |

## MongoDB layout

One database, one collection per scraper. Configure in [`mongodb.toml`](mongodb.toml):

```toml
[mongodb]
uri = "mongodb://localhost:27017"
database = "vulnerabilities"
conflict = "overwrite"

[mongodb.collections]
avd = "avd"
cisco = "cisco"
# ... one entry per scraper key
```

Precedence: env vars (`MONGO_URI`, `MONGO_DB`) > `mongodb.toml` > defaults.

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
vuln-scrape review
vuln-scrape migrate-mongo --target-version 2 --dry-run
```
