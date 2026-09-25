# Add a New Scraper

This document is the source-of-truth checklist for adding a new scraper to this project.

Use `<provider>` as the provider key (example: `zeroday`), and `<ProviderName>` as the class name (example: `ZeroDayProvider`).

## 1) Required folder structure

Create this structure under `vuln_scraper/scrapers/`:

```text
vuln_scraper/scrapers/<provider>/
  config.py
  provider.py
  parsers/
    list.py
    detail.py
```

Also add tests and fixtures:

```text
tests/scrapers/<provider>/
  fixtures/
    list.html          # when content_type is "html"
    detail.html
    list.json          # when content_type is "json"
    detail.json
  test_provider.py
  test_parsers.py
```

## 2) Files to create (new provider package)

- `vuln_scraper/scrapers/<provider>/config.py`
  - Define constants like `BASE_URL`, `LIST_URL`, `SOURCE_URL`. A legacy
    `DEFAULT_COLLECTION` may remain for migration discovery, but runtime writes
    always use the shared collection.
- `vuln_scraper/scrapers/<provider>/provider.py`
  - Add a `@dataclass` provider with fields:
    - `key`
    - `source_url`
    - `default_mongo_collection`
    - `content_type` (`"html"` or `"json"`)
    - `default_request_delay`
    - `stop_on_first_known`
  - Implement:
    - `list_url(self, page, *, checkpoint=None) -> str`
    - `detail_url(self, identity_display: str) -> str`
    - `parse_list(self, content, *, page: int) -> ListPage`
    - `parse_detail(self, content)`
- `vuln_scraper/scrapers/<provider>/parsers/list.py`
  - Parse list response into `ListPage` + `ListEntry`.
- `vuln_scraper/scrapers/<provider>/parsers/detail.py`
  - Parse detail response into a typed detail record with `to_dict()`.
- `tests/scrapers/<provider>/test_provider.py`
  - Validate URL behavior, registry inclusion, and provider defaults.
- `tests/scrapers/<provider>/test_parsers.py`
  - Validate list/detail parser behavior using fixture HTML/JSON.

## 3) Project wiring (automatic)

### `vuln_scraper/scrapers/__init__.py`

- Nothing to edit: providers are discovered automatically from the package
  directories. `provider.py` must expose either a `PROVIDER_CLASS` attribute or
  a single class whose `key` field equals the directory name. A package that
  fails to import is skipped with a warning instead of breaking the CLI.
- Optional: export `PROVIDER_SCHEMA` (a `schema_v2.ProviderSchema`) from
  `provider.py` to register document normalization with the provider; otherwise
  add the schema to the built-in table in `schema_v2.py`.

### `vuln_scraper/config.py`

- Runtime collection routing is global. Do not add provider-specific collection
  routing; every provider is distinguished by `source.provider`.

### `mongodb.toml`

- No provider entry is needed. The single `[mongodb].collection` value applies
  to every provider.

### `scrapers.toml` (optional)

- Add `[scrapers.<provider>]` to tune `retries`, `backoff_base`, `backoff_max`,
  `backoff_jitter`, and CNVD-only `session_max_retries` / `session_retry_delay`.
- Add `[scrapers.catch_up]` with `providers = ["all"]` or a provider list such as
  `providers = ["hkcert", "cve"]` to control which scrapers `vuln-scrape catch-up`
  runs. Omit the section to run all scrapers.
- Failures append to the combined log configured by `[scrapers.defaults] error_log`.

### `README.md`

- Add the scraper to:
  - MongoDB layout table
  - Development scraper tree
  - Any provider-specific notes (request behavior, fallback mode, source URL)

### Test files (where relevant)

- `tests/test_config.py`
  - Update expected collections map assertions (for example
    `test_mongo_collection_for_provider_uses_collections_table`).
- `tests/test_catch_up.py`
  - Add catch-up behavior tests if the provider has special stop/progress rules.
- `tests/test_runner.py`
  - Add provider-specific run behavior tests if needed (for example stop-on-known logic).

## 4) Implementation checklist

- [ ] Provider key is lowercase and stable (`<provider>`).
- [ ] Stored documents use the shared collection and set `source.provider`.
- [ ] `content_type` matches real endpoint payload (`html` vs `json`).
- [ ] `list_url` and `detail_url` are deterministic and correctly encoded.
- [ ] Parser output includes stable identity fields (`type`, `code`, optional `cve_code`).
- [ ] `details.<provider>` structure is consistent and serializable.
- [ ] New provider appears in `provider_keys()` and `get_provider()`.
- [ ] Sync cycle includes provider and writes to intended Mongo collection.
- [ ] Tests pass.

## 5) Quick verification commands

```bash
PYTHONPATH=. pytest -q
PYTHONPATH=. pytest -q tests/scrapers/<provider>
```

## Removing a provider

- Delete `vuln_scraper/scrapers/<provider>/` and `tests/scrapers/<provider>/`;
  discovery picks the change up automatically.
- Remove its key from the `[scrapers.catch_up] providers` list in
  `scrapers.toml` (optional — unknown keys are skipped with a warning) and its
  row from the README table.
- Keep its `ProviderSchema` entry in `schema_v2.py` if historical documents of
  that provider exist, so `migrate-mongo`/`unify-mongo` can still normalize them.
