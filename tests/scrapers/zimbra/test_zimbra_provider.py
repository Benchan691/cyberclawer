from vuln_scraper.scrapers import ZimbraProvider, get_provider, provider_keys


def test_zimbra_provider_is_registered() -> None:
    provider = ZimbraProvider()

    assert "zimbra" in provider_keys()
    assert get_provider("zimbra").key == "zimbra"
    assert provider.list_url(1) == "https://wiki.zimbra.com/wiki/Zimbra_Releases"
    assert provider.detail_url("ZIMBRA-10.1.20") == (
        "https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20"
    )
    assert provider.detail_url("ZIMBRA-8.8.15/P47") == (
        "https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P47"
    )
