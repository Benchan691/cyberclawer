from vuln_scraper.providers import CNVDProvider, get_provider, provider_keys


def test_cnvd_provider_registry_and_defaults() -> None:
    provider = get_provider("cnvd")

    assert isinstance(provider, CNVDProvider)
    assert "cnvd" in provider_keys()
    assert provider.content_type == "html"
    assert not provider.browser_fallback
    assert not provider.always_use_browser
    assert not provider.manual_verification
    assert provider.default_mongo_collection == "cnvd"
    assert provider.default_request_delay == 3.0
    assert provider.default_concurrency == 1
    assert provider.stop_on_first_known


def test_cnvd_provider_urls() -> None:
    provider = CNVDProvider()

    assert provider.list_url(1) == "https://www.cnvd.org.cn/flaw/list?max=20&offset=0"
    assert provider.list_url(3) == "https://www.cnvd.org.cn/flaw/list?max=20&offset=40"
    assert provider.detail_url("CNVD-2026-21550") == "https://www.cnvd.org.cn/flaw/show/CNVD-2026-21550"
