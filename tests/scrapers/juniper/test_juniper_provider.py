from vuln_scraper.models import ListEntry, VulnerabilityId
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

    assert (
        provider.source_url
        == "https://supportportal.juniper.net/s/global-search/%40uri#f-sf_primarysourcename=Knowledge"
        "&f-sf_articletype=Security%20Advisories"
    )
    assert provider.list_url(1).startswith("https://supportportal.juniper.net/s/global-search/%40uri#")
    assert "f-sf_primarysourcename=Knowledge" in provider.list_url(1)
    assert "f-sf_articletype=Security%20Advisories" in provider.list_url(1)
    assert "firstResult=0" in provider.list_url(1)
    assert "firstResult=10" in provider.list_url(2)
    assert provider.detail_url("JUNIPER-JSA93456") == "https://supportportal.juniper.net/s/article/JSA93456"


def test_juniper_provider_uses_list_detail_link_when_available() -> None:
    provider = JuniperProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="JUNIPER", code="JSA108949"),
        title="2026-05 Reference Advisory",
        vuln_type="Security Advisories",
        disclosure_date="2026-06-01",
        status="Security Advisories",
        provider="juniper",
        embedded_detail={
            "reference_links": [
                "https://supportportal.juniper.net/s/article/2026-05-Reference-Advisory-Status-of-Copy-Fail-vulnerability-on-Juniper-Products-CVE-2026-31431"
            ]
        },
    )

    assert (
        provider.detail_url_for_entry(entry)
        == "https://supportportal.juniper.net/s/article/2026-05-Reference-Advisory-Status-of-Copy-Fail-vulnerability-on-Juniper-Products-CVE-2026-31431"
    )
