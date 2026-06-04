from vuln_scraper.providers import ZeroDayProvider, get_provider, provider_keys


def test_zero_day_provider_urls_and_registry() -> None:
    provider = ZeroDayProvider()

    assert "zeroday" in provider_keys()
    assert get_provider("zeroday").key == "zeroday"
    assert provider.list_url(1) == "https://www.zero-day.cz/database/"
    assert provider.list_url(99) == "https://www.zero-day.cz/database/"
    assert provider.detail_url("ZERODAY-1101") == "https://www.zero-day.cz/database/1101/"
    assert provider.default_mongo_collection == "zeroday"
    assert provider.stop_on_first_known
