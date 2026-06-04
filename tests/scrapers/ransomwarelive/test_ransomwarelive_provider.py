import pytest

from vuln_scraper.providers import RansomwareLiveProvider, get_provider, provider_keys
from vuln_scraper.scrapers.ransomwarelive.provider import RansomwareLiveAuthError


def test_ransomwarelive_provider_urls_and_registry() -> None:
    provider = RansomwareLiveProvider()

    assert "ransomwarelive" in provider_keys()
    assert get_provider("ransomwarelive").key == "ransomwarelive"
    assert provider.list_url(1) == "https://api-pro.ransomware.live/victims/recent?order=discovered"
    assert provider.list_url(99) == "https://api-pro.ransomware.live/victims/recent?order=discovered"
    assert provider.detail_url("RANSOMWARELIVE-abc123") == "https://api-pro.ransomware.live/victim/abc123"
    assert provider.default_mongo_collection == "ransomwarelive"
    assert provider.content_type == "json"
    assert provider.stop_on_first_known


def test_ransomwarelive_provider_uses_api_key_header(monkeypatch) -> None:
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", " secret-key ")
    monkeypatch.setenv("RANSOM_API_KEY", "alias-key")

    assert RansomwareLiveProvider().request_headers() == {
        "Accept": "application/json",
        "X-API-KEY": "secret-key",
    }


def test_ransomwarelive_provider_accepts_ransom_api_key_alias(monkeypatch) -> None:
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.setenv("RANSOM_API_KEY", " alias-key ")

    assert RansomwareLiveProvider().request_headers() == {
        "Accept": "application/json",
        "X-API-KEY": "alias-key",
    }


def test_ransomwarelive_provider_loads_api_key_from_dotenv(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.delenv("RANSOM_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('export RANSOM_API_KEY="dotenv-key"\n', encoding="utf-8")

    assert RansomwareLiveProvider().request_headers() == {
        "Accept": "application/json",
        "X-API-KEY": "dotenv-key",
    }


def test_ransomwarelive_provider_missing_api_key_raises(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.delenv("RANSOM_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(RansomwareLiveAuthError):
        RansomwareLiveProvider().request_headers()
