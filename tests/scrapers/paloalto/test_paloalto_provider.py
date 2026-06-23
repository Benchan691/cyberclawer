from vuln_scraper.scrapers import PaloAltoProvider, get_provider, provider_keys


def test_paloalto_provider_urls_and_registry() -> None:
    provider = PaloAltoProvider()

    assert "paloalto" in provider_keys()
    assert get_provider("paloalto").key == "paloalto"
    assert provider.list_url(1) == "https://security.paloaltonetworks.com/?page=1&limit=100"
    assert provider.list_url(3) == "https://security.paloaltonetworks.com/?page=3&limit=100"
    assert provider.detail_url("PALOALTO-CVE-2026-0265") == "https://security.paloaltonetworks.com/CVE-2026-0265"
    assert (
        provider.detail_url("PALOALTO-PAN-SA-2026-0007")
        == "https://security.paloaltonetworks.com/PAN-SA-2026-0007"
    )
    assert provider.default_mongo_collection == "paloalto"
    assert not provider.browser_fallback
    assert provider.stop_on_first_known
