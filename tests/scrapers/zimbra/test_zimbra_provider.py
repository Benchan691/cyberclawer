from urllib.parse import parse_qs, urlsplit

from vuln_scraper.scrapers import ZimbraProvider, get_provider, provider_keys


def test_zimbra_provider_is_registered() -> None:
    provider = ZimbraProvider()

    assert "zimbra" in provider_keys()
    assert get_provider("zimbra").key == "zimbra"
    feed = urlsplit(provider.list_url(1))
    assert (feed.scheme, feed.netloc, feed.path) == ("https", "wiki.zimbra.com", "/api.php")
    query = parse_qs(feed.query)
    assert query["action"] == ["feedrecentchanges"]
    assert query["feedformat"] == ["rss"]
    assert query["target"] == ["Zimbra_Releases"]
    assert provider.catch_up_full_feed
    assert not provider.stop_on_first_known
    assert provider.detail_url("ZIMBRA-10.1.20") == (
        "https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20"
    )
    assert provider.detail_url("ZIMBRA-8.8.15/P47") == (
        "https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P47"
    )
