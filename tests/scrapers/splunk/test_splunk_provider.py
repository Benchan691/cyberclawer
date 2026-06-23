import pytest

from vuln_scraper.scrapers import SplunkProvider, get_provider, provider_keys


def test_splunk_provider_registry_and_defaults() -> None:
    provider = get_provider("splunk")

    assert isinstance(provider, SplunkProvider)
    assert "splunk" in provider_keys()
    assert provider.content_type == "html"
    assert not provider.browser_fallback
    assert provider.default_request_delay == 1.0
    assert provider.stop_on_first_known
    assert provider.default_mongo_collection == "splunk"


def test_splunk_provider_urls() -> None:
    provider = SplunkProvider()

    assert provider.list_url(1) == "https://advisory.splunk.com"
    assert provider.list_url(99) == "https://advisory.splunk.com"
    assert provider.detail_url("SPLUNK-SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"
    assert provider.detail_url("SVD-2026-0516") == "https://advisory.splunk.com/advisories/SVD-2026-0516"


def test_splunk_provider_rejects_invalid_detail_id() -> None:
    with pytest.raises(ValueError):
        SplunkProvider().detail_url("SPLUNK-2026-0516")
