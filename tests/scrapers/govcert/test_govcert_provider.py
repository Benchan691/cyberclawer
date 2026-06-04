from vuln_scraper.providers import GovCERTProvider, get_provider, provider_keys


def test_govcert_provider_urls_and_registry() -> None:
    provider = GovCERTProvider()

    assert "govcert" in provider_keys()
    assert get_provider("govcert").key == "govcert"
    assert provider.list_url(1) == "https://www.govcert.gov.hk/en/alerts.php?page=1"
    assert provider.list_url(2) == "https://www.govcert.gov.hk/en/alerts.php?page=2"
    assert provider.detail_url("GOVCERT-1894") == "https://www.govcert.gov.hk/en/alerts_detail.php?id=1894"
    assert provider.default_mongo_collection == "govcert"
    assert not provider.browser_fallback
    assert provider.stop_on_first_known
