from vuln_scraper.providers import AVDProvider, get_provider, provider_keys


def test_avd_provider_registry_and_defaults() -> None:
    provider = get_provider("avd")

    assert isinstance(provider, AVDProvider)
    assert "avd" in provider_keys()
    assert provider.content_type == "html"
    assert provider.browser_fallback
    assert provider.default_mongo_collection == "avd"
    assert provider.default_request_delay == 1.0
    assert not provider.stop_on_first_known


def test_avd_provider_urls() -> None:
    provider = AVDProvider()

    assert provider.list_url(1) == "https://avd.aliyun.com/high-risk/list?page=1"
    assert provider.detail_url("AVD-2026-10001") == "https://avd.aliyun.com/detail?id=AVD-2026-10001"
