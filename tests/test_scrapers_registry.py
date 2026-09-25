import logging

import pytest

from vuln_scraper.scrapers import (
    all_providers,
    get_provider,
    provider_keys,
)


EXPECTED_KEYS = (
    "avd",
    "cnvd",
    "cve",
    "github_advisory",
    "hkcert",
    "hpe",
    "huawei_sa",
    "juniper",
    "msrc",
    "nvd",
    "paloalto",
    "qianxin",
    "splunk",
    "zimbra",
)


def test_registry_discovers_provider_packages() -> None:
    keys = provider_keys()
    assert keys == EXPECTED_KEYS
    assert keys == tuple(sorted(keys))


def test_get_provider_returns_fresh_instances() -> None:
    first = get_provider("hkcert")
    second = get_provider("hkcert")
    assert first is not second
    assert first.key == "hkcert"


def test_get_provider_unknown_key_lists_choices() -> None:
    with pytest.raises(KeyError) as excinfo:
        get_provider("does-not-exist")
    message = str(excinfo.value)
    assert "does-not-exist" in message
    assert "hkcert" in message


def test_all_providers_covers_registry() -> None:
    providers = all_providers()
    assert sorted(provider.key for provider in providers) == list(EXPECTED_KEYS)


def test_discovery_skips_nonconforming_packages(monkeypatch, caplog) -> None:
    import vuln_scraper.scrapers as scrapers_pkg

    warmed_cache = dict(scrapers_pkg._providers())
    original_import_module = scrapers_pkg.importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name.endswith(".provider") and "hkcert" in name:
            raise ImportError(f"boom: {name}")
        return original_import_module(name, *args, **kwargs)

    monkeypatch.setattr(scrapers_pkg.importlib, "import_module", fake_import)
    monkeypatch.setattr(scrapers_pkg, "_DISCOVERED", None)
    with caplog.at_level(logging.WARNING):
        keys = scrapers_pkg.provider_keys()

    assert "hkcert" not in keys
    assert any("hkcert" in record.message for record in caplog.records)

    # restore the cache explicitly (the import patch is still active here)
    monkeypatch.setattr(scrapers_pkg, "_DISCOVERED", warmed_cache)
    assert "hkcert" in scrapers_pkg.provider_keys()
