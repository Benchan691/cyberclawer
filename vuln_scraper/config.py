from __future__ import annotations

import os
import tomllib
import socket
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any



DEFAULT_DATA_DIR = Path("data")
DEFAULT_OUTPUT_FILE = DEFAULT_DATA_DIR / "high_risk_vulns.json"
DEFAULT_CHECKPOINT_FILE = DEFAULT_DATA_DIR / "checkpoint.json"
DEFAULT_MONGO_FILTERED_OUTPUT_FILE = DEFAULT_DATA_DIR / "mongo_filtered_vulns.json"
MAX_RESULT_LIMIT = 1000
DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_MONGO_DATABASE = "vulnerabilities"
DEFAULT_MONGO_COLLECTION = "vulnerabilities"
DEFAULT_MONGO_COLLECTIONS = {
    "avd": "avd",
    "hkcert": "hkcert",
    "cve": "cve",
    "cisco": "cisco",
    "zeroday": "zeroday",
    "govcert": "govcert",
    "github_advisory": "github_advisory",
    "huawei_sa": "huawei_sa",
    "paloalto": "paloalto",
    "qianxin": "qianxin",
    "ransomwarelive": "ransomwarelive",
    "infosec": "infosec",
    "splunk": "splunk",
    "hikvision": "hikvision",
    "cnnvd": "cnnvd",
    "cnvd": "cnvd",
    "juniper": "juniper",
    "msrc": "msrc",
}
DEFAULT_MONGO_CONFIG_FILE = Path("mongodb.toml")
DEFAULT_SCRAPERS_CONFIG_FILE = Path("scrapers.toml")
MONGO_CONFLICT_MODES = {"prompt", "skip", "overwrite"}

DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_BASE = 1.0
DEFAULT_BACKOFF_MAX = 30.0
DEFAULT_BACKOFF_JITTER = 0.4
DEFAULT_ERROR_LOG_NAME = "scraper-errors.log"
DEFAULT_CNVD_SESSION_MAX_RETRIES = 50
DEFAULT_CNVD_SESSION_RETRY_DELAY = 0.3

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


def _env(name: str, *, legacy: str | None = None) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    if legacy:
        return os.getenv(legacy)
    return None


def resolve_proxy_url(*, explicit: str | None = None) -> str | None:
    if explicit and explicit.strip():
        proxy = explicit.strip()
        return proxy if _local_proxy_reachable(proxy) else None
    for name in ("SCRAPER_PROXY", "HTTPS_PROXY", "HTTP_PROXY"):
        value = _env(name)
        if value and value.strip():
            proxy = value.strip()
            return proxy if _local_proxy_reachable(proxy) else None
    return None


def _local_proxy_reachable(proxy_url: str, *, timeout_seconds: float = 0.5) -> bool:
    """
    For local proxies only (127.0.0.1/localhost), treat connection-refused as "proxy off".
    This prevents scrapers from failing when a local proxy is misconfigured or stopped.
    """
    try:
        from urllib.parse import urlparse

        parsed = urlparse(proxy_url)
        host = (parsed.hostname or "").lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return True
        port = parsed.port
        if port is None:
            # Default ports for typical proxy schemes.
            port = 443 if (parsed.scheme or "").lower() == "https" else 80

        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def apply_httpx_proxy_kwargs(kwargs: dict[str, Any], proxy: str | None) -> None:
    """Apply proxy settings to httpx.AsyncClient kwargs; disable TLS verify behind proxy."""
    if not proxy or not proxy.strip():
        return
    kwargs["proxy"] = proxy.strip()
    kwargs["trust_env"] = False
    kwargs["verify"] = False


def configure_requests_session_proxy(session: Any, proxy_url: str | None) -> None:
    """Configure a requests.Session for proxy use; disable TLS verify behind proxy."""
    if not proxy_url or not proxy_url.strip():
        return
    url = proxy_url.strip()
    session.proxies.update({"http": url, "https": url})
    session.verify = False
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass


def default_chrome_executable() -> str | None:
    env_path = _env("SCRAPER_CHROME_PATH", legacy="AVD_CHROME_PATH")
    if env_path:
        return env_path

    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


@dataclass(slots=True)
class ScraperRetryConfig:
    retries: int = DEFAULT_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_max: float = DEFAULT_BACKOFF_MAX
    backoff_jitter: float = DEFAULT_BACKOFF_JITTER
    session_max_retries: int | None = None
    session_retry_delay: float | None = None
    error_log: str | None = DEFAULT_ERROR_LOG_NAME


@dataclass(slots=True)
class ScraperSettings:
    limit: int = MAX_RESULT_LIMIT
    mongo_enabled: bool = False
    mongo_uri: str | None = None
    mongo_database: str | None = None
    mongo_collection: str | None = None
    mongo_config_file: Path | None = DEFAULT_MONGO_CONFIG_FILE
    mongo_conflict: str | None = None
    mongo_interactive: bool = False
    request_delay: float = 1.0
    concurrency: int = 3
    retries: int = DEFAULT_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_max: float = DEFAULT_BACKOFF_MAX
    backoff_jitter: float = DEFAULT_BACKOFF_JITTER
    session_max_retries: int | None = None
    session_retry_delay: float | None = None
    scrapers_config_file: Path | None = DEFAULT_SCRAPERS_CONFIG_FILE
    error_log: str | None = DEFAULT_ERROR_LOG_NAME
    timeout: float = 30.0
    data_dir: Path = DEFAULT_DATA_DIR
    output_file: Path = DEFAULT_OUTPUT_FILE
    checkpoint_file: Path = DEFAULT_CHECKPOINT_FILE
    browser_fallback: bool = False
    browser_headless: bool = True
    browser_timeout_ms: int = 30_000
    browser_user_data_dir: Path | None = None
    manual_verification: bool = False
    manual_verification_timeout_ms: int = 300_000
    chrome_executable: str | None = None
    proxy_url: str | None = None

    def for_provider(
        self,
        provider_key: str,
        *,
        default_collection: str | None = None,
        browser_fallback: bool | None = None,
        default_request_delay: float | None = None,
        default_concurrency: int | None = None,
        manual_verification: bool | None = None,
    ) -> "ScraperSettings":
        mongo_collection = self.mongo_collection
        env_collection = _env("MONGO_COLLECTION", legacy="AVD_MONGO_COLLECTION")
        if env_collection is None and (
            mongo_collection is None or mongo_collection == DEFAULT_MONGO_COLLECTION
        ):
            mongo_collection = mongo_collection_for_provider(
                provider_key,
                self.mongo_config_file,
                default=default_collection,
            )
        request_delay = self.request_delay
        if default_request_delay is not None and self.request_delay == 1.0:
            request_delay = default_request_delay
        concurrency = self.concurrency
        if default_concurrency is not None and self.concurrency == 3:
            concurrency = max(1, default_concurrency)
        provider_manual_verification = self.manual_verification if manual_verification is None else manual_verification
        browser_headless = self.browser_headless
        browser_user_data_dir = self.browser_user_data_dir
        browser_timeout_ms = self.browser_timeout_ms
        if provider_manual_verification:
            browser_headless = False
            browser_timeout_ms = max(browser_timeout_ms, self.manual_verification_timeout_ms)
            if browser_user_data_dir is None:
                browser_user_data_dir = Path(self.data_dir) / "browser_profiles" / provider_key
        resolved_browser_fallback = self.browser_fallback if browser_fallback is None else browser_fallback
        if provider_key == "cnvd":
            resolved_browser_fallback = False

        retry_cfg = retry_config_for_provider(provider_key, self.scrapers_config_file)
        retries = self.retries
        if self.retries == DEFAULT_RETRIES:
            retries = retry_cfg.retries
        backoff_base = self.backoff_base
        if self.backoff_base == DEFAULT_BACKOFF_BASE:
            backoff_base = retry_cfg.backoff_base
        backoff_max = self.backoff_max
        if self.backoff_max == DEFAULT_BACKOFF_MAX:
            backoff_max = retry_cfg.backoff_max
        backoff_jitter = self.backoff_jitter
        if self.backoff_jitter == DEFAULT_BACKOFF_JITTER:
            backoff_jitter = retry_cfg.backoff_jitter
        error_log = self.error_log
        if self.error_log == DEFAULT_ERROR_LOG_NAME:
            error_log = retry_cfg.error_log

        session_max_retries = self.session_max_retries
        session_retry_delay = self.session_retry_delay
        if provider_key == "cnvd":
            if session_max_retries is None and retry_cfg.session_max_retries is not None:
                session_max_retries = retry_cfg.session_max_retries
            if session_retry_delay is None and retry_cfg.session_retry_delay is not None:
                session_retry_delay = retry_cfg.session_retry_delay
            if session_max_retries is None:
                session_max_retries = DEFAULT_CNVD_SESSION_MAX_RETRIES
            if session_retry_delay is None:
                session_retry_delay = DEFAULT_CNVD_SESSION_RETRY_DELAY

        return replace(
            self,
            mongo_collection=mongo_collection,
            browser_fallback=resolved_browser_fallback,
            request_delay=request_delay,
            concurrency=concurrency,
            browser_headless=browser_headless,
            browser_timeout_ms=browser_timeout_ms,
            browser_user_data_dir=browser_user_data_dir,
            manual_verification=provider_manual_verification,
            retries=retries,
            backoff_base=backoff_base,
            backoff_max=backoff_max,
            backoff_jitter=backoff_jitter,
            session_max_retries=session_max_retries,
            session_retry_delay=session_retry_delay,
            error_log=error_log,
        )

    def normalized(self) -> "ScraperSettings":
        data_dir = Path(self.data_dir)
        output_file = Path(self.output_file)
        checkpoint_file = Path(self.checkpoint_file)
        browser_user_data_dir = Path(self.browser_user_data_dir) if self.browser_user_data_dir is not None else None

        if output_file == DEFAULT_OUTPUT_FILE:
            output_file = data_dir / DEFAULT_OUTPUT_FILE.name
        if checkpoint_file == DEFAULT_CHECKPOINT_FILE:
            checkpoint_file = data_dir / DEFAULT_CHECKPOINT_FILE.name

        chrome_executable = self.chrome_executable
        if self.browser_fallback and not chrome_executable:
            chrome_executable = default_chrome_executable()

        if not 1 <= self.limit <= MAX_RESULT_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
        mongo_config = load_mongo_config(self.mongo_config_file)
        mongo_conflict = self.mongo_conflict or _optional_config_str(mongo_config, "conflict") or "prompt"

        if mongo_conflict not in MONGO_CONFLICT_MODES:
            choices = ", ".join(sorted(MONGO_CONFLICT_MODES))
            raise ValueError(f"mongo_conflict must be one of: {choices}")

        mongo_uri = (
            self.mongo_uri
            or _env("MONGO_URI", legacy="AVD_MONGO_URI")
            or _optional_config_str(mongo_config, "uri")
            or DEFAULT_MONGO_URI
        )
        mongo_database = (
            self.mongo_database
            or _env("MONGO_DB", legacy="AVD_MONGO_DB")
            or _optional_config_str(mongo_config, "database")
            or DEFAULT_MONGO_DATABASE
        )
        mongo_collection = (
            self.mongo_collection
            or _env("MONGO_COLLECTION", legacy="AVD_MONGO_COLLECTION")
            or _optional_config_str(mongo_config, "collection")
            or DEFAULT_MONGO_COLLECTION
        )

        return ScraperSettings(
            limit=self.limit,
            mongo_enabled=self.mongo_enabled,
            mongo_uri=mongo_uri,
            mongo_database=mongo_database,
            mongo_collection=mongo_collection,
            mongo_config_file=self.mongo_config_file,
            mongo_conflict=mongo_conflict,
            mongo_interactive=self.mongo_interactive,
            request_delay=self.request_delay,
            concurrency=self.concurrency,
            retries=self.retries,
            backoff_base=self.backoff_base,
            backoff_max=self.backoff_max,
            backoff_jitter=self.backoff_jitter,
            session_max_retries=self.session_max_retries,
            session_retry_delay=self.session_retry_delay,
            scrapers_config_file=self.scrapers_config_file,
            error_log=self.error_log,
            timeout=self.timeout,
            data_dir=data_dir,
            output_file=output_file,
            checkpoint_file=checkpoint_file,
            browser_fallback=self.browser_fallback,
            browser_headless=self.browser_headless,
            browser_timeout_ms=self.browser_timeout_ms,
            browser_user_data_dir=browser_user_data_dir,
            manual_verification=self.manual_verification,
            manual_verification_timeout_ms=self.manual_verification_timeout_ms,
            chrome_executable=chrome_executable,
            proxy_url=resolve_proxy_url(explicit=self.proxy_url),
        )


def load_scrapers_config(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {}

    config_path = Path(path)
    if not config_path.exists():
        return {}

    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    scrapers = data.get("scrapers", data)
    if not isinstance(scrapers, dict):
        raise ValueError(f"{config_path} must contain a scrapers config table")
    return scrapers


def _scraper_table(config: dict[str, Any], key: str) -> dict[str, Any]:
    section = config.get(key, {})
    return section if isinstance(section, dict) else {}


def _optional_config_int(config: dict[str, Any], key: str) -> int | None:
    value = config.get(key)
    if value is None:
        return None
    return int(value)


def _optional_config_float(config: dict[str, Any], key: str) -> float | None:
    value = config.get(key)
    if value is None:
        return None
    return float(value)


def catch_up_provider_keys(
    path: Path | str | None = DEFAULT_SCRAPERS_CONFIG_FILE,
) -> tuple[str, ...] | None:
    """Return configured catch-up provider keys, or None to run every provider."""
    config = load_scrapers_config(path)
    catch_up = _scraper_table(config, "catch_up")
    if "providers" not in catch_up:
        return None

    raw = catch_up["providers"]
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError(f"{path} [scrapers.catch_up] providers must be a list of provider keys")

    keys: list[str] = []
    seen: set[str] = set()
    for item in raw:
        key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        keys.append(key)
    if keys == ["all"]:
        return None
    if "all" in keys:
        raise ValueError(f"{path} [scrapers.catch_up] providers cannot mix 'all' with specific provider keys")
    return tuple(keys)


def retry_config_for_provider(
    provider_key: str,
    path: Path | str | None = DEFAULT_SCRAPERS_CONFIG_FILE,
) -> ScraperRetryConfig:
    config = load_scrapers_config(path)
    defaults = _scraper_table(config, "defaults")
    provider = _scraper_table(config, provider_key)

    merged: dict[str, Any] = {**defaults, **provider}
    error_log = _optional_config_str(merged, "error_log")
    if error_log is not None and not error_log.strip():
        error_log = None

    return ScraperRetryConfig(
        retries=int(merged.get("retries", DEFAULT_RETRIES)),
        backoff_base=float(merged.get("backoff_base", DEFAULT_BACKOFF_BASE)),
        backoff_max=float(merged.get("backoff_max", DEFAULT_BACKOFF_MAX)),
        backoff_jitter=float(merged.get("backoff_jitter", DEFAULT_BACKOFF_JITTER)),
        session_max_retries=_optional_config_int(merged, "session_max_retries"),
        session_retry_delay=_optional_config_float(merged, "session_retry_delay"),
        error_log=error_log if error_log is not None else DEFAULT_ERROR_LOG_NAME,
    )


def error_log_path_for_settings(settings: ScraperSettings) -> Path | None:
    if not settings.error_log:
        return None
    name = Path(settings.error_log.strip()).name
    if not name:
        return None
    return (Path(settings.data_dir) / name).resolve()


def load_mongo_config(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {}

    config_path = Path(path)
    if not config_path.exists():
        return {}

    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    mongo = data.get("mongodb", data)
    if not isinstance(mongo, dict):
        raise ValueError(f"{config_path} must contain a MongoDB config table")
    return mongo


def mongo_collections_from_config(path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE) -> dict[str, str]:
    config = load_mongo_config(path)
    configured = config.get("collections", {})
    collections = dict(DEFAULT_MONGO_COLLECTIONS)
    if isinstance(configured, dict):
        collections.update(
            {
                str(provider).strip(): str(collection).strip()
                for provider, collection in configured.items()
                if str(provider).strip() and str(collection).strip()
            }
        )
    return dict(sorted(collections.items()))


def mongo_collection_for_provider(
    provider_key: str,
    path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
    *,
    default: str | None = None,
) -> str:
    collections = mongo_collections_from_config(path)
    return collections.get(provider_key, default or DEFAULT_MONGO_COLLECTION)


def provider_for_mongo_collection(
    collection_name: str,
    path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
) -> str | None:
    for provider_key, configured_collection in mongo_collections_from_config(path).items():
        if configured_collection == collection_name:
            return provider_key
    return None


def default_scrape_settings(*, limit: int = MAX_RESULT_LIMIT, mongo_enabled: bool = True) -> ScraperSettings:
    return ScraperSettings(
        limit=limit,
        mongo_enabled=mongo_enabled,
        mongo_config_file=DEFAULT_MONGO_CONFIG_FILE,
        browser_fallback=False,
        mongo_interactive=False,
    )


def mongo_filtered_output_file(data_dir: Path, collection: str) -> Path:
    safe_collection = collection.strip().replace("/", "_") or "records"
    default_name = DEFAULT_MONGO_FILTERED_OUTPUT_FILE.name
    if safe_collection == DEFAULT_MONGO_COLLECTION:
        return Path(data_dir) / default_name
    return Path(data_dir) / f"mongo_filtered_{safe_collection}.json"


def resolve_mongo_export_path(data_dir: Path, name: str, *, default_name: str) -> Path:
    cleaned = Path(name.strip() or default_name).name
    if not cleaned:
        cleaned = default_name
    if not cleaned.lower().endswith(".json"):
        cleaned = f"{cleaned}.json"
    return Path(data_dir) / cleaned


def _optional_config_str(config: dict[str, Any], key: str) -> str | None:
    value = config.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None
