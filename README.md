# Vulnerability Bulletin Scrapers

Terminal scrapers ingest vulnerability bulletins into MongoDB, and `mongodb-filter`
browses, reads, and exports filtered records from the same database. There is no web UI.

## Install

Use Python 3.11 or newer.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For Aliyun AVD HTTP scraping (sigchl redirect bypass via quickjs), install:

```bash
pip install -e '.[avd]'
```

For scrapers that need a real browser or browser-assisted cookie capture
(Hikvision; AVD as fallback), install the optional browser extra:

```bash
pip install -e '.[browser,avd]'
```

HKCERT, zero-day.cz, GovCERT.HK,
InfoSec, Splunk, and Palo Alto Networks advisories are server-rendered HTML and
do not use browser fallback. Aliyun AVD solves the `sigchl` challenge with
quickjs on each list and detail URL, follows the generated redirect, then parses
the cleared HTML. List row links from `tbody` are used as detail targets. The
provider also accepts a raw Cookie header through `AVD_COOKIE`,
`AVD_COOKIES`, or `ALIYUN_AVD_COOKIE`. Browser fallback still applies when the
redirect response is blocked. Use `--no-browser-fallback` only when HTTP +
quickjs clearance is sufficient on your network.
Hikvision renders through the browser path. Juniper uses the Coveo search API
(JSON). CVE sync consumes the CVEProject cvelistV5 delta log. Cisco PSIRT, CNNVD, and Qianxin sync
call JSON APIs directly. Huawei SA sync calls Huawei's JSON advisory endpoint;
set `HUAWEI_SA_X_CK` and `HUAWEI_SA_CSRF_TOKEN` if the endpoint requires browser
session tokens. CNVD uses HTTP with an optional `cnvd` extra
(`quickjs`, `ddddocr`, `requests`) to solve the site gate and persist cookies.

## HTTP proxy

Scraper outbound HTTP(S) traffic (API calls, HTML fetch, browser fallback, AVD/CNVD
side paths) can use a proxy without affecting the MongoDB connection. Set
`SCRAPER_PROXY` in the project `.env` (loaded at startup), or pass `--proxy` on
`run` / `catch-up`:

```bash
# .env
SCRAPER_PROXY=http://127.0.0.1:7890

python scrape.py tui
python scrape.py run avd --limit 10 --proxy http://127.0.0.1:7890
```

If `SCRAPER_PROXY` is unset, `HTTPS_PROXY` and then `HTTP_PROXY` are used. Prefer
`SCRAPER_PROXY` over global `HTTP_PROXY` when only scrapers should be proxied.

When a proxy is configured, TLS certificate verification is disabled for scraper
HTTP clients (common for HTTPS intercepting proxies). MongoDB connections are
unchanged.

## MongoDB Layout

All scrapers use one MongoDB database, with one collection per scraper.

| Scraper folder | MongoDB collection | Ingest CLI |
| --- | --- | --- |
| `vuln_scraper/scrapers/avd/` | `avd` | `python scrape.py run avd --limit 100` / `python scrape.py tui` |
| `vuln_scraper/scrapers/hkcert/` | `hkcert` | `python scrape.py tui` / `python scrape.py catch-up` |
| `vuln_scraper/scrapers/cve/` | `cve` | same |
| `vuln_scraper/scrapers/cisco/` | `cisco` | same |
| `vuln_scraper/scrapers/zeroday/` | `zeroday` | same |
| `vuln_scraper/scrapers/govcert/` | `govcert` | same |
| `vuln_scraper/scrapers/github_advisory/` | `github_advisory` | same |
| `vuln_scraper/scrapers/huawei_sa/` | `huawei_sa` | same |
| `vuln_scraper/scrapers/paloalto/` | `paloalto` | same |
| `vuln_scraper/scrapers/qianxin/` | `qianxin` | same |
| `vuln_scraper/scrapers/ransomwarelive/` | `ransomwarelive` | same |
| `vuln_scraper/scrapers/infosec/` | `infosec` | same |
| `vuln_scraper/scrapers/splunk/` | `splunk` | same |
| `vuln_scraper/scrapers/hikvision/` | `hikvision` | same |
| `vuln_scraper/scrapers/cnnvd/` | `cnnvd` | same |
| `vuln_scraper/scrapers/cnvd/` | `cnvd` | `pip install -e '.[cnvd]'` then `python scrape.py run cnvd --limit 100` |
| `vuln_scraper/scrapers/juniper/` | `juniper` | same |

`mongodb.toml`:

```toml
[mongodb]
uri = "mongodb://localhost:27017"
database = "vulnerabilities"
conflict = "prompt"

[mongodb.collections]
avd = "avd"
hkcert = "hkcert"
cve = "cve"
cisco = "cisco"
zeroday = "zeroday"
govcert = "govcert"
github_advisory = "github_advisory"
huawei_sa = "huawei_sa"
paloalto = "paloalto"
qianxin = "qianxin"
ransomwarelive = "ransomwarelive"
infosec = "infosec"
splunk = "splunk"
hikvision = "hikvision"
cnnvd = "cnnvd"
cnvd = "cnvd"
juniper = "juniper"
```

Precedence for connection settings is CLI flags, environment variables
(`MONGO_URI`, `MONGO_DB`, `MONGO_COLLECTION`; legacy `AVD_MONGO_*` names still
work), `mongodb.toml`, then built-in defaults. The `[mongodb.collections]` table
maps each scraper to its collection inside the configured database.

For MongoDB Atlas, set `MONGO_URI` to your `mongodb+srv://` connection string
(do not commit credentials into `mongodb.toml`):

```bash
export MONGO_URI='mongodb+srv://user:password@cluster.example.mongodb.net'
```

Each synced vulnerability document includes a top-level `severity` field with
normalized English labels (`Critical`, `High`, `Medium`, `Low`, `Unknown`, or
empty when unavailable). Provider-specific severity values remain under
`details.<provider>`. The filter TUI exposes `severity` as a shared categorical
field across collections; review views store the same normalized value in
`impacts`. To backfill existing source collections without re-scraping:

```bash
python scrape.py backfill-severity
python scrape.py backfill-severity cnnvd hikvision --dry-run
```

Then refresh review views with `python scrape.py review`. Alternatively,
re-scrape with `--mongo-conflict overwrite`.

`scrapers.toml` configures per-scraper HTTP retries, exponential backoff, and
the combined run log filename. Precedence is explicit `ScraperSettings` values,
then `[scrapers.<provider>]`, then `[scrapers.defaults]`, then built-in defaults.

```toml
[scrapers.defaults]
retries = 3
backoff_base = 1.0
backoff_max = 30.0
backoff_jitter = 0.4
error_log = "scraper-errors.log"

[scrapers.cnvd]
retries = 5
backoff_base = 2.0
session_max_retries = 50
session_retry_delay = 0.3
```

During a scrape, INFO-or-higher logger messages are appended as JSON lines to
`{data_dir}/scraper-errors.log` (or the configured name). Explicit scrape
failures also append structured `record_type="failure"` JSON lines.
Set `error_log = ""` under `[scrapers.defaults]` to disable file logging.

## Usage

Interactive scrape, choosing scraper and amount:

```bash
python scrape.py tui
```

Catch up every provider: scrape and sync in batches until MongoDB overlap or the
per-provider `--limit` is reached, then move to the next provider (no sleep between
providers):

```bash
python scrape.py catch-up
python scrape.py catch-up --limit 200 --max-runs-per-provider 50
```

With `--limit 200`, each provider/collection scrapes at most 200 records total
across all catch-up runs for that provider before advancing.

Run one scraper once, for example AVD (browser extra recommended) or CNVD (requires the `cnvd` extra):

```bash
pip install -e '.[browser]'
python scrape.py run avd --limit 100

pip install -e '.[cnvd]'
python scrape.py run cnvd --limit 100
```

Filter and browse records in MongoDB:

```bash
mongodb-filter
mongodb-filter --mongo-config mongodb.toml
mongodb-filter --mongo-collection hkcert
```

Without `--mongo-collection`, `mongodb-filter` opens a collection picker using
`[mongodb.collections]`. Filtering stays in the terminal: checkbox fields,
text-contains fields, paged result browsing, record read (Enter on a result), and
JSON export (`e` in the TUI — prompts for a filename under `data/`; if the file
already exists, choose replace or rename).

## Document Shape

Each document is keyed by unique lowercase scraper `type` + provider-native
`code`, with `_id` such as `avd:2026-42945`,
`hkcert:suse-linux-kernel-multiple-vulnerabilities_20260601`,
`huawei_sa:huawei-sa-LKEiSHPVtLPEDF-60937345`, or `cve:2024-3094`. Common fields live at the top level:

- `type`, `code`, `cve_code`, `title`, `disclosure_date`, `status`, `severity`
- `source`
- `details`

Provider-specific fields live under `details.<provider>`.

When a detail response contains HTML tables, every table is also preserved under
`details.<provider>.raw_tables` as a rectangular 2D array of cleaned cell text.
The outer array contains tables in response order, and each table includes its
header and data rows. This field is written to both JSON scrape output and
MongoDB alongside existing provider-specific semantic table fields.

Aliyun AVD detail fields include `danger_level`, `exploitability`, `patch_status`,
`description`, `impact_range`, `security_versions`, `solution`, `reference_links`,
`cwe`, `attack_metrics`, and `affected_software`.
HKCERT detail fields include `intro`, `table`, `note`, `impact` (array),
`systems_affected` (array), `solutions`, `solution_links`, `vulnerability_identifiers`,
`bulletin_source`, `related_links`, `risk_level`, `release_date`,
`last_update_date`, `views`, and `summary`. Product-table bulletins store each
row under `table` with `name`, `risk_level`,
`impacts`, `notes`, `details`, and optional `details_url`.
zero-day.cz detail fields include `advisory`, `vulnerable_component`,
`cvss_v3_vector`, `cwe`, `description`, `patch_status`, and `reference_links`.
GovCERT.HK detail fields include `alert_code`, `alert_type`, `published_date`,
`description`, `affected_systems`, `impact`, `recommendation`,
`more_information_links`, `tags`, `cve_ids`, and `raw_sections`. Huawei SA records
preserve the advisory API payload under `details.huawei_sa` and add `cve_ids`
when non-empty CVE IDs are present in Huawei's `vul` list. Cisco OpenVuln detail fields include `advisory_id`, `advisory_title`, `sir`,
`first_published`, `last_updated`, `cve_ids`, `bug_ids`, `cwe`,
`cvss_base_score`, `product_names`, `publication_url`, `summary`, and `raw`.
GitHub Advisory detail fields include `ghsa_id`, `cve_id`, `cve_ids`,
`summary`, `description`, `advisory_type`, `severity`, `html_url`,
`api_url`, `source_code_location`, `identifiers`, `references`, timestamps,
`vulnerabilities`, `cvss`, `cvss_severities`, `cwes`, `epss`, `credits`, and
`raw`.
Palo Alto Networks detail fields include `advisory_id`, `severity`, `urgency`,
`cvss_score`, `cvss_vector`, `published_date`, `updated_date`, `products`,
`product_status`, `weakness`, `impact`, `solution`, `timeline`, `cve_ids`, and
`raw_sections`.
Qianxin detail records store the six article chapters under `description` as
`security_advisory` (string), `vulnerability_information` (object),
`threat_assessment` (object), `affected_assets` (string), `recommendations`
(array), and `references` (array). The chapter 2 and 3 objects normalize their
tables, including affected versions, risk/status fields, and CVSS assessment
fields. The trailing Qianxin CERT profile section is excluded.
Ransomware.live detail fields include `victim`, `group`, `attackdate`,
`discovered`, `country`, `activity`, `website`, `screenshot`, `infostealer`,
`press`, `permalink`, and `raw`.
InfoSec detail fields include `alert_code`, `alert_type`, `published_date`,
`summary`, `description`, `affected_systems`, `impact`, `recommendation`,
`more_information_links`, `tags`, `cve_ids`, `raw_sections`, and
`govcert_detail_url`.
Splunk detail fields include `advisory_id`, `cve_ids`, `published_date`,
`last_modified`, `cvss_vector`, `cvss_score`, `cwe`, `bug_ids`,
`affected_products`, `fixed_versions`, `affected_versions`,
`affected_components`, `description`, `solution`, `mitigations`,
`severity_summary`, `packages`, `product_status`, `credit`, and
`reference_links`.
CVEs from HKCERT/zero-day.cz/GovCERT.HK/Cisco/Huawei SA/Palo Alto Networks/
InfoSec/Splunk details are stored as top-level `cve_code` using the normalized
`YYYY-NNNN` form. Non-CVE bulletins use `cve_code = null`.
CNNVD stores the inner detail API object unchanged under `details.cnnvd`, using
the source field names such as `id`, `vulName`, `cnnvdCode`, `cveCode`,
`hazardLevel`, `vulDesc`, `affectedProduct`, `affectedSystem`, `referUrl`, and
`patch`.
CNVD detail fields include `cnvd_id`, `severity`, `cvss_score`,
`cvss_vector`, `affected_products`, `cve_ids`, `description`, `solution`,
`reference_links`, `published_date`, and `raw_fields`.

CVE master records use `type = "cve"`, `code = "YYYY-NNNN"`, `cve_code = null`,
and store normalized CVE v5 fields under `details.cve`, including descriptions,
CVSS metrics, affected product/version lines, references, and a complete `raw`
copy for forward compatibility.

## Development

Scrapers live under:

```text
vuln_scraper/scrapers/
  __init__.py
  avd/
  cisco/
  cnnvd/
  cve/
  govcert/
  github_advisory/
  hikvision/
  hkcert/
  huawei_sa/
  infosec/
  juniper/
  cnvd/
  qianxin/
  ransomwarelive/
  splunk/
  zeroday/
```

Each scraper owns its URL config, provider, filter fields, and parsers.

Run tests:

```bash
PYTHONPATH=. uv run pytest -q
```

## Operational Notes

These scrapers are for personal or research use. Keep conservative request pacing
and stop if a site returns rate-limit or challenge responses persistently. HKCERT
bulletin pages are public,
server-rendered HTML at [Security Bulletin](https://www.hkcert.org/security-bulletin).
zero-day.cz records are scraped from [Zero-day Vulnerability Database](https://www.zero-day.cz/database/);
Mongo sync treats that feed as newest-first and stops once it reaches a stored
record to avoid historical backfill.
GovCERT.HK security alerts are scraped from [Security Alerts](https://www.govcert.gov.hk/en/alerts.php)
and use the same newest-first sync stop behavior. Huawei SA advisories are
retrieved from Huawei's enterprise security advisory JSON endpoint with a POST
payload equivalent to the standalone Huawei bulletin script.
GitHub reviewed advisories are ingested from the
[Global Security Advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)
using `type=reviewed`, `sort=published`, `direction=desc`, and `per_page=100`.
Set `GITHUB_TOKEN` to send a bearer token for higher GitHub API rate limits;
without it, the scraper uses public unauthenticated access. Mongo sync stops at
the first stored advisory.
InfoSec security alerts are scraped from [Security Alerts and Advisories](https://www.infosec.gov.hk/en/news-events/security-alerts-and-advisories)
year pages and use linked GovCERT detail pages for full advisory content.
Palo Alto Networks advisories are scraped from [Security Advisories](https://security.paloaltonetworks.com/)
and use the same newest-first sync stop behavior.
Qianxin risk notices are ingested from the JSON endpoints behind
[漏洞通告](https://ti.qianxin.com/vulnerability/notice-list): `article-notice`
for newest-first lists and `article-detail` for article HTML. Mongo sync stops
at the first stored notice.
Splunk advisories are scraped from [Splunk Security Advisories](https://advisory.splunk.com/).
The homepage advisory table is newest-first, and detail pages under
`/advisories/SVD-...` provide CVE, CVSS, CWE, package remediation, product
status, solution, and severity fields. Mongo sync stops once it reaches a stored
Splunk advisory.
Hikvision advisories are scraped from [Security Advisory](https://www.hikvision.com/hk/support/cybersecurity/security-advisory/).
The public page may return a Tencent EdgeOne JavaScript challenge, so this
provider uses browser rendering by default and stops Mongo sync at the first
stored advisory.
Aliyun AVD high-risk advisories are scraped from
[AVD 高危漏洞](https://avd.aliyun.com/high-risk/list). Install `pip install -e '.[avd]'`.
Each list and detail fetch runs the sigchl inline script in quickjs, follows the
redirect URL (`timestamp__1384=...`), and parses that HTML. Detail pages use the
`tbody` row link href when present. Playwright remains a fallback when redirect
clearance fails. Optional env cookie: `AVD_COOKIE` / `AVD_COOKIES` /
`ALIYUN_AVD_COOKIE`.
CNNVD vulnerabilities are ingested from the JSON endpoints behind
[漏洞信息](https://www.cnnvd.org.cn/home/loophole): `homePage/cnnvdVulList` for
newest-first lists and `cnnvdVul/getCnnnvdDetailOnDatasource` for details.
Detail requests use the list record ID, CNNVD code, CVE code, and vulnerability
type, with reduced compatibility payloads as fallbacks. The runner consumes
every ID from each fetched list page before requesting the next page.
Mongo sync stops at the first stored vulnerability.
CNVD flaws are scraped from [漏洞列表](https://www.cnvd.org.cn/flaw/list) over HTTP.
Install the CNVD gate dependencies with `pip install -e '.[cnvd]'`. On each run
the scraper refreshes session cookies in memory (Jiasule clearance + captcha OCR)
and passes them to httpx—no cookie JSON file is required. List and detail pages
are synced into the `cnvd` MongoDB collection; Mongo sync stops at the first
stored flaw. To authenticate and scrape in one step, run
`python vuln_scraper/scrapers/cnvd/crawler_ng/getter.py --data-dir data --limit 100`.
Juniper advisories are ingested from the Coveo search API behind the
[Support Portal security advisory search](https://supportportal.juniper.net/s/global-search/%40uri#f-sf_primarysourcename=Knowledge&f-sf_articletype=Security%20Advisories).
List and detail requests POST to Coveo; HTML parsers remain as a fallback when
JSON is unavailable. Mongo sync stops at the first stored advisory.
Ransomware.live victims are ingested from the
[API PRO](https://api-pro.ransomware.live/) `/victims/recent` endpoint. Set
`RANSOMWARE_LIVE_API_KEY` or `RANSOM_API_KEY`; the scraper sends it as
`X-API-KEY`. These can be exported in the shell or placed in a project `.env`
file. The API PRO
documentation currently lists a 500,000 requests/month quota per key. Mongo sync
treats this feed as newest-first and stops once it reaches a stored victim.

The CVE scraper uses the
[CVEProject cvelistV5 delta log](https://github.com/CVEProject/cvelistV5).
Each run reads the delta log newest-first, skips CVEs already stored in MongoDB,
and fetches up to the requested limit of new records from GitHub. Mongo sync uses
the same conflict handling as other providers.

The Cisco scraper uses the [PSIRT OpenVuln API](https://developer.cisco.com/docs/psirt/).
Cisco requires an access token for every OpenVuln API request. Set
`CISCO_OPENVULN_TOKEN` to use an existing Bearer token, or set
`CISCO_OPENVULN_CLIENT_ID` (or `CISCO_OPENVULN_CLIENT_KEY`) and
`CISCO_OPENVULN_CLIENT_SECRET` so the scraper can obtain and cache an OAuth
client-credentials token from Cisco. The shorter `CISCO_CLIENT_ID`,
`CISCO_CLIENT_KEY`, and `CISCO_CLIENT_SECRET` names are also accepted. These can
be exported in the shell or placed in a project `.env` file (loaded automatically
when you run `python scrape.py` or `vuln-scrape`).
