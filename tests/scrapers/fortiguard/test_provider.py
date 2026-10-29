from vuln_scraper.scrapers import FortiguardProvider, get_provider, provider_keys


def test_fortiguard_provider_urls_and_registry() -> None:
    provider = FortiguardProvider()

    assert "fortiguard" in provider_keys()
    assert get_provider("fortiguard").key == "fortiguard"
    assert provider.list_url(1) == "https://www.fortiguard.com/psirt?page=1&filter=1"
    assert provider.list_url(3) == "https://www.fortiguard.com/psirt?page=3&filter=1"
    assert provider.detail_url("FORTIGUARD-FG-IR-26-160") == "https://www.fortiguard.com/psirt/FG-IR-26-160"
    assert provider.default_mongo_collection == "fortiguard"
    assert not provider.browser_fallback
    assert provider.content_type == "html"
    assert provider.stop_on_first_known
