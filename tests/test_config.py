import pytest

from vuln_scraper.scrapers import all_providers, provider_keys
from vuln_scraper.config import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_BACKOFF_JITTER,
    DEFAULT_BACKOFF_MAX,
    DEFAULT_RETRIES,
    MAX_RESULT_LIMIT,
    ScraperSettings,
    USER_AGENT_POOL,
    default_scrape_settings,
    load_mongo_config,
    load_scrapers_config,
    catch_up_provider_keys,
    mongo_collection_for_provider,
    mongo_collections_from_config,
    random_user_agent,
    retry_config_for_provider,
)


def test_load_mongo_config_reads_mongodb_table(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        conflict = "overwrite"
        """,
        encoding="utf-8",
    )

    config = load_mongo_config(config_file)

    assert config["uri"] == "mongodb://config.test:27017"
    assert config["database"] == "config_db"
    assert config["collection"] == "config_collection"
    assert config["conflict"] == "overwrite"


def test_scraper_settings_use_mongo_config_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("MONGO_URI", raising=False)
    monkeypatch.delenv("MONGO_DB", raising=False)
    monkeypatch.delenv("MONGO_COLLECTION", raising=False)
    monkeypatch.delenv("AVD_MONGO_URI", raising=False)
    monkeypatch.delenv("AVD_MONGO_DB", raising=False)
    monkeypatch.delenv("AVD_MONGO_COLLECTION", raising=False)
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        conflict = "skip"
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).normalized()

    assert settings.mongo_uri == "mongodb://config.test:27017"
    assert settings.mongo_database == "config_db"
    assert settings.mongo_collection == "config_collection"
    assert settings.mongo_conflict == "skip"


def test_environment_values_override_mongo_config_file(tmp_path, monkeypatch) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("AVD_MONGO_URI", "mongodb://env.test:27017")
    monkeypatch.setenv("AVD_MONGO_DB", "env_db")
    monkeypatch.setenv("AVD_MONGO_COLLECTION", "env_collection")

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).normalized()

    assert settings.mongo_uri == "mongodb://env.test:27017"
    assert settings.mongo_database == "env_db"
    assert settings.mongo_collection == "env_collection"


def test_default_scrape_settings_enables_mongo_without_provider_browser_default() -> None:
    settings = default_scrape_settings(limit=25).normalized()

    assert settings.limit == 25
    assert settings.mongo_enabled
    assert not settings.browser_fallback
    assert settings.limit <= MAX_RESULT_LIMIT


def test_mongo_collection_for_provider_uses_collections_table(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "vulnerabilities"

        [mongodb.collections]
        hkcert = "hkcert"
        ransomwarelive = "ransomwarelive"
        """,
        encoding="utf-8",
    )

    assert mongo_collections_from_config(config_file) == dict(sorted(
        (provider.key, provider.default_mongo_collection)
        for provider in all_providers()
    ))
    assert mongo_collection_for_provider("hkcert", config_file) == "hkcert"


def test_mongo_collections_from_config_is_alphabetical() -> None:
    keys = list(mongo_collections_from_config().keys())
    assert keys == sorted(keys)


def test_provider_keys_is_alphabetical() -> None:
    assert provider_keys() == tuple(sorted(provider_keys()))


def test_scraper_settings_for_provider_disables_browser_for_cnvd() -> None:
    settings = ScraperSettings(browser_fallback=True).for_provider("cnvd")

    assert settings.browser_fallback is False


def test_scraper_settings_for_provider_overrides_default_collection(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        database = "vulnerabilities"

        [mongodb.collections]
        hkcert = "hkcert"
        """,
        encoding="utf-8",
    )

    settings = (
        ScraperSettings(mongo_enabled=True, mongo_config_file=config_file)
        .normalized()
        .for_provider("hkcert")
        .normalized()
    )

    assert settings.mongo_collection == "hkcert"


def test_scraper_settings_for_provider_sets_collection(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        database = "vulnerabilities"

        [mongodb.collections]
        hkcert = "hkcert"
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).for_provider("hkcert").normalized()

    assert settings.mongo_collection == "hkcert"


def test_load_scrapers_config_reads_scrapers_table(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.defaults]
        retries = 2
        backoff_base = 0.5

        [scrapers.cnvd]
        retries = 7
        session_max_retries = 10
        """,
        encoding="utf-8",
    )

    config = load_scrapers_config(config_file)

    assert config["defaults"]["retries"] == 2
    assert config["cnvd"]["retries"] == 7


def test_retry_config_for_provider_merges_defaults_and_provider(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.defaults]
        retries = 2
        backoff_base = 0.5
        backoff_max = 10.0

        [scrapers.cve]
        retries = 5
        backoff_base = 2.0
        """,
        encoding="utf-8",
    )

    cfg = retry_config_for_provider("cve", config_file)

    assert cfg.retries == 5
    assert cfg.backoff_base == 2.0
    assert cfg.backoff_max == 10.0


def test_scraper_settings_for_provider_applies_scrapers_toml(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.defaults]
        retries = 2

        [scrapers.hkcert]
        retries = 4
        backoff_base = 1.5
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(scrapers_config_file=config_file).for_provider("hkcert")

    assert settings.retries == 4
    assert settings.backoff_base == 1.5


def test_scraper_settings_for_provider_keeps_explicit_retries(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.hkcert]
        retries = 9
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(retries=6, scrapers_config_file=config_file).for_provider("hkcert")

    assert settings.retries == 6


def test_scraper_settings_for_provider_applies_cnvd_session_retries(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.cnvd]
        session_max_retries = 12
        session_retry_delay = 0.7
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(scrapers_config_file=config_file).for_provider("cnvd")

    assert settings.session_max_retries == 12
    assert settings.session_retry_delay == 0.7


def test_scraper_settings_for_provider_uses_defaults_when_unset() -> None:
    settings = ScraperSettings().for_provider("hkcert")

    assert settings.retries == DEFAULT_RETRIES
    assert settings.backoff_base == DEFAULT_BACKOFF_BASE
    assert settings.backoff_max == DEFAULT_BACKOFF_MAX
    assert settings.backoff_jitter == DEFAULT_BACKOFF_JITTER


def test_catch_up_provider_keys_returns_none_when_unconfigured(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.defaults]
        retries = 2
        """,
        encoding="utf-8",
    )

    assert catch_up_provider_keys(config_file) is None


def test_catch_up_provider_keys_reads_provider_list(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["hkcert", "cve", "hkcert"]
        """,
        encoding="utf-8",
    )

    assert catch_up_provider_keys(config_file) == ("hkcert", "cve")


def test_catch_up_provider_keys_all_runs_every_provider(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["all"]
        """,
        encoding="utf-8",
    )

    assert catch_up_provider_keys(config_file) is None


def test_catch_up_provider_keys_rejects_all_mixed_with_specific_providers(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["all", "hkcert"]
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cannot mix 'all'"):
        catch_up_provider_keys(config_file)


def test_catch_up_provider_keys_rejects_non_list(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = "hkcert"
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="providers must be a list"):
        catch_up_provider_keys(config_file)


def test_random_user_agent_returns_pool_member() -> None:
    ua = random_user_agent()
    assert ua in USER_AGENT_POOL


def test_random_user_agent_excludes_current() -> None:
    for candidate in USER_AGENT_POOL:
        rotated = random_user_agent(exclude=candidate)
        assert rotated != candidate
        assert rotated in USER_AGENT_POOL
