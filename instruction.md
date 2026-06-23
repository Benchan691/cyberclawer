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
  - Define constants like `BASE_URL`, `LIST_URL`, `SOURCE_URL`, `DEFAULT_COLLECTION`.
- `vuln_scraper/scrapers/<provider>/provider.py`
  - Add a `@dataclass` provider with fields:
    - `key`
    - `source_url`
    - `default_mongo_collection`
    - `browser_fallback`
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

## 3) Files to edit (project wiring)

### `vuln_scraper/scrapers/__init__.py`

- Import the new provider class.
- Add provider to `PROVIDERS` (dict insertion order controls `catch-up` iteration;
  `provider_keys()` is sorted alphabetically for CLI/help).

### `vuln_scraper/mongo_filter.py`

- Add provider-specific categorical/text paths to `FILTER_FIELDS`.

### `vuln_scraper/config.py`

- Set `default_mongo_collection` on the provider; add a `[mongodb.collections]`
  override only when the configured collection name differs.

### `mongodb.toml`

- Add `<provider> = "<collection>"` under `[mongodb.collections]`.

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
- `tests/test_mongo_filter.py`
  - Add `filter_fields_for_provider("<provider>")` coverage.

## 4) Implementation checklist

- [ ] Provider key is lowercase and stable (`<provider>`).
- [ ] `default_mongo_collection` matches config/toml/test expectations.
- [ ] `content_type` matches real endpoint payload (`html` vs `json`).
- [ ] `list_url` and `detail_url` are deterministic and correctly encoded.
- [ ] Parser output includes stable identity fields (`type`, `code`, optional `cve_code`).
- [ ] `details.<provider>` structure is consistent and serializable.
- [ ] `FILTER_FIELDS` paths point to real document paths.
- [ ] New provider appears in `provider_keys()` and `get_provider()`.
- [ ] Sync cycle includes provider and writes to intended Mongo collection.
- [ ] Tests pass.

## 5) Quick verification commands

```bash
PYTHONPATH=. uv run pytest -q
PYTHONPATH=. uv run pytest -q tests/scrapers/<provider>
```
