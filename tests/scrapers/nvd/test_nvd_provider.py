from pathlib import Path

from vuln_scraper.scrapers.nvd.provider import NvdProvider


def test_nvd_provider_registry_and_defaults() -> None:
    from vuln_scraper.scrapers import get_provider, provider_keys

    assert "nvd" in provider_keys()
    provider = get_provider("nvd")
    assert isinstance(provider, NvdProvider)
    assert provider.content_type == "json"
    assert provider.default_mongo_collection == "nvd"
    # Unauthenticated NVD allows 5 requests per 30s window.
    assert provider.default_request_delay >= 6.0


def test_nvd_provider_urls() -> None:
    provider = NvdProvider(page_size=200)

    url = provider.list_url(1)
    assert url.startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert "resultsPerPage=200" in url
    assert "startIndex=0" in url
    assert "lastModStartDate=" in url and "lastModEndDate=" in url

    second = provider.list_url(2)
    assert "startIndex=200" in second

    assert provider.detail_url("CVE-2026-1234") == "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"


def test_nvd_detail_url_for_entry_embeds_details() -> None:
    provider = NvdProvider()

    class Entry:
        display_id = "CVE-2026-1234"
        embedded_detail = {"cve_id": "CVE-2026-1234"}

    assert provider.detail_url_for_entry(Entry()) is None

    class BareEntry:
        display_id = "CVE-2026-1234"
        embedded_detail = None

    assert provider.detail_url_for_entry(BareEntry()) == "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"


def test_nvd_request_headers_use_env_key(monkeypatch) -> None:
    provider = NvdProvider()

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert provider.request_headers() == {}

    monkeypatch.setenv("NVD_API_KEY", " test-key ")
    assert provider.request_headers() == {"apiKey": "test-key"}


def test_nvd_list_url_window_is_bounded() -> None:
    provider = NvdProvider(window_days=120)
    url = provider.list_url(1)
    assert "lastModStartDate=" in url
    # API cap: date windows may not exceed 120 days.
    assert provider.window_days == 120
