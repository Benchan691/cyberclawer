# The Hacker News: setup and deployment guide

Prepared on 24 November 2026 for the existing HKCTTSECADV deployment.
This guide is for a future manual rollout; deployment was stopped at the user's request.

## Released changes

| Component | Repository / branch | Commit |
| --- | --- | --- |
| Scraper | `Benchan691/cyberclawer`, `main` | [`f51ebe1`](https://github.com/Benchan691/cyberclawer/commit/f51ebe103d8e44b0b0d8633a1281c633474719da) |
| Webserver | `Benchan691/WEBSEVER`, `redesign/unified-news-collection` | [`b86c121`](https://github.com/Benchan691/WEBSEVER/commit/b86c1211d4e892b3aeb7929795aad412ac476f6c) |

Both commits are pushed. Later commits may include other changes; review them
separately before choosing a release version.

Before the stop request, the server's scraper source catalog was refreshed.
The webserver patch was checked but was not applied, built, or restarted.
No The Hacker News collection run was started on the production server as part
of this change. Confirm the current server state before any later rollout,
because other maintenance may have continued independently.

## Feed and collection rules

- Provider key: `the_hacker_news`.
- Discovery: <https://feeds.feedburner.com/TheHackersNews>, with no index or archive fallback.
- Full article pages supply article text, author, topics, publication/revision dates,
  references, and CVEs when present. Denied article access switches the run to RSS
  summaries. These records have `details.content_source = "rss"`.
- The existing `--days 1` setting means **today in Hong Kong**, using an article's
  publication or revision date. Feed rebuild and collection times do not qualify
  old stories. No historical recovery is added.
- A valid run may insert zero records, particularly immediately after midnight
  when the current feed contains only yesterday's articles.
- Records use `source.provider = "the_hacker_news"` in the existing `news`
  collection. IDs are `the_hacker_news:YYYY-MM-permalink-slug`.
- Existing articles are compared before writing; unchanged runs do not replace
  documents. Articles that leave RSS remain stored. Failed details remain retryable.
- General news receives no invented severity, CVSS, or CVE. Articles without CVEs
  can still be reviewed, previewed, and auto-selected by their stable record ID.

See [schema and operations](THE_HACKER_NEWS.md) and the webserver's
[integration guide](https://github.com/Benchan691/WEBSEVER/blob/b86c1211d4e892b3aeb7929795aad412ac476f6c/docs/THE_HACKER_NEWS_INTEGRATION.md).

## Existing server locations

| Item | Location |
| --- | --- |
| Scraper | `/home/cpcnet/cyberclawer` |
| Scraper executable | `/home/cpcnet/cyberclawer/.venv/bin/vuln-scrape` |
| Scraper settings | `/home/cpcnet/cyberclawer/scrapers.toml` |
| Webserver source | `/home/cpcnet/webserver-rust-zimbra-candidate` |
| Existing container | `webserver-rust-candidate` |
| Compose service | `web` |
| Existing application port | `9100` |

Keep the hourly cron entry:

```cron
0 * * * * cd /home/cpcnet/cyberclawer && /home/cpcnet/cyberclawer/.venv/bin/vuln-scrape catch-up --days 1 >> /home/cpcnet/cyberclawer/scrape.log 2>&1
```

## Before updating

1. Check `git status --short` and `git log -1 --oneline` in both server directories.
   The existing webserver has local customizations; preserve them. Its working
   files may already contain changes newer than its recorded Git commit.
2. Back up the affected source files, `.env`, `scrapers.toml`, `mongodb.toml`,
   `docker-compose.yml`, webserver `config/`, the current cron entry, and Docker
   inspection output. Protect backups containing credentials from other users.
3. Tag the running webserver image for rollback. Check for runtime files or mounted
   newsletter/report output that must survive container replacement.
4. Preserve MongoDB subscriptions, email queues, delivery receipts, and newsletter
   display-reset settings. This feature requires **no database migration or reset**.
5. Compare the running container's environment, port bindings, volumes, and restart
   settings with Compose. Resolve differences before replacing the container.

A backup made before the rollout was stopped is located at:

```text
/home/cpcnet/deploy-backups/the-hacker-news-20261123T160107Z
```

Its rollback image tag is
`webserver-rust-candidate:before-thn-20261123t160107z`.
Check that these backups still exist, and make a fresh backup for a later rollout.

## Update the scraper

Review the target version before updating. For a checkout whose local changes do
not overlap the release, the reviewed scraper commit can be integrated with:

```bash
cd /home/cpcnet/cyberclawer
git fetch origin main
git merge --ff-only f51ebe103d8e44b0b0d8633a1281c633474719da
```

If Git reports conflicting local changes, retain them and reconcile the source
before continuing. Do not force an overwrite. This provider adds no dependencies.

The current selection already enables it:

```toml
[scrapers.catch_up]
providers = ["all"]
```

For an explicit provider list, add `"the_hacker_news"` while retaining the existing
entries. Then refresh the catalog:

```bash
./.venv/bin/vuln-scrape sync-source-catalog
```

## Update the existing webserver

1. Fetch `redesign/unified-news-collection` and review commit `b86c121`.
2. Integrate its The Hacker News changes into a copy of the current server source,
   preserving local Wiz, review, subscription, newsletter-reset, and other edits.
   A direct patch check against the existing dirty checkout reported a context
   conflict in `src/subscriptions.rs`; reconcile that change before building.
   Do not resolve it by replacing the whole file with the committed version.
3. Run the Rust tests and formatting checks on the resulting source. Retain the
   existing `.env`, Compose file, configuration, ports, and delivery state.
4. Build the existing service while the current container remains running:

   ```bash
   cd /home/cpcnet/webserver-rust-zimbra-candidate
   docker compose build web
   ```

5. After a successful build and configuration comparison, replace that service:

   ```bash
   docker compose up -d --no-deps web
   ```

Use the host's existing Docker access method. Keep the deployment in this
directory; do not start a second production instance.

## Verify after a future rollout

1. Confirm the existing site responds on port `9100` and ordinary sign-in works.
2. In Subscriptions, check that `the_hacker_news` is offered from the refreshed
   source catalog. Explicit source selections stay unchanged; dynamic all-source
   selections include new providers. Reviews lists the source once records exist.
3. Run only this provider, twice, using the current date window:

   ```bash
   cd /home/cpcnet/cyberclawer
   ./.venv/bin/vuln-scrape run the_hacker_news --days 1 --limit 1000
   ./.venv/bin/vuln-scrape run the_hacker_news --days 1 --limit 1000
   ```

   Both runs use the shared process lock. If an hourly job holds it, wait for that
   job to finish. Check completion, pending retries, and MongoDB errors separately.
   The second run should perform no inserts or replacements unless the source
   changed. Zero eligible records is valid; do not widen the date window merely
   to make an insert happen.
4. Independently inspect MongoDB with this filter:

   ```javascript
   { "source.provider": "the_hacker_news" }
   ```

   Check `_id`, `source.detail_url`, source dates, and full `details.content` or
   the RSS summary and `details.content_source` marker.
   Confirm that `observed_at` has not turned an old story into current news.
5. In Reviews, apply the source filter and a keyword from the full article body.
   Open a newsletter preview. Check author, topics, paragraphs, references, and
   actual CVEs; general news should not show invented advisory fields. Where
   available, confirm auto-selection includes a story without a CVE.
6. Confirm `.env`, Compose configuration, cron, and saved subscription settings
   remain unchanged. Do not send test newsletters to real recipients, clear email
   queues, reset delivery receipts, or reset displayed records for this rollout.

## Rollback

Restore only the changed source files from the fresh backup and replace the web
service with the tagged previous image, retaining its configuration and runtime
data. Verify port `9100` and sign-in again. No database rollback is needed for this
feature. Do not delete collected articles or delivery state to roll back code.

To temporarily stop this source while investigating an issue, use an explicit
catch-up provider list that retains the other providers and omits
`the_hacker_news`, then refresh the source catalog. Preserve the hourly cron entry.

## Validation completed before handoff

The isolated scraper change passed 520 tests, with two existing skips. Two unrelated
classifier test modules could not be collected because `vendor_product_classifier`
is absent from this checkout. All 16 new scraper tests passed, covering full text,
RSS validation, stable IDs, old-story exclusion, revisions, limits, and recovery.

The isolated webserver change passed formatting and 87 Rust tests. Its dedicated
MongoDB integration test also passed, covering keyword search, severity handling,
same-CVE news articles, articles without CVEs, and subscription matching. Additional
integration tests passed against a disposable local MongoDB. Live RSS and two live
article pages were parsed and validated against schema v2 without production writes.
