from vuln_scraper.providers import JuniperProvider, get_provider, provider_keys


def test_juniper_provider_registry_and_defaults() -> None:
    provider = get_provider("juniper")

    assert isinstance(provider, JuniperProvider)
    assert "juniper" in provider_keys()
    assert provider.content_type == "html"
    assert provider.browser_fallback
    assert provider.always_use_browser
    assert provider.default_mongo_collection == "juniper"
    assert provider.stop_on_first_known


def test_juniper_provider_urls() -> None:
    provider = JuniperProvider()

    assert provider.list_url(1).startswith("https://supportportal.juniper.net/s/global-search/%40uri#")
    assert "firstResult=0" in provider.list_url(1)
    assert "firstResult=10" in provider.list_url(2)
    assert provider.detail_url("JUNIPER-JSA93456") == "https://supportportal.juniper.net/s/article/JSA93456"
