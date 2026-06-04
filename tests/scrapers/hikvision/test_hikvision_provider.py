from vuln_scraper.providers import HikvisionProvider, get_provider, provider_keys


def test_hikvision_provider_registry_and_defaults() -> None:
    provider = get_provider("hikvision")

    assert isinstance(provider, HikvisionProvider)
    assert "hikvision" in provider_keys()
    assert provider.content_type == "html"
    assert provider.browser_fallback
    assert provider.always_use_browser
    assert provider.default_mongo_collection == "hikvision"
    assert provider.stop_on_first_known


def test_hikvision_provider_urls() -> None:
    provider = HikvisionProvider()

    assert provider.list_url(1) == "https://www.hikvision.com/hk/support/cybersecurity/security-advisory/"
    assert provider.list_url(2).endswith("?page=2")
    assert (
        provider.detail_url("HIKVISION-hsrc-2026-0001")
        == "https://www.hikvision.com/hk/support/cybersecurity/security-advisory/hsrc-2026-0001/"
    )
    assert provider.detail_url("HIKVISION-security-vulnerabilities-in-hikvision-nvr-devices").endswith(
        "/content/hikvision/hk/support/cybersecurity/security-advisory/"
        "security-vulnerabilities-in-hikvision-nvr-devices.html"
    )
