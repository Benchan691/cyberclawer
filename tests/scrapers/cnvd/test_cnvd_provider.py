from vuln_scraper.scrapers import CNVDProvider, get_provider, provider_keys
from vuln_scraper.models import ListEntry, VulnerabilityId


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


def test_cnvd_provider_uses_list_detail_link_for_entry() -> None:
    provider = CNVDProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="CNVD", code="2010-00001"),
        title="Legacy Product 漏洞",
        vuln_type=None,
        disclosure_date="2010-01-01",
        status="中",
        provider="cnvd",
        embedded_detail={"reference_links": ["https://www.cnvd.org.cn/flaw/show/12345"]},
    )

    assert provider.detail_url_for_entry(entry) == "https://www.cnvd.org.cn/flaw/show/12345"


def test_cnvd_provider_does_not_invent_entry_detail_link() -> None:
    provider = CNVDProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="CNVD", code="2010-00001"),
        title="Legacy Product 漏洞",
        vuln_type=None,
        disclosure_date="2010-01-01",
        status="中",
        provider="cnvd",
        embedded_detail={"reference_links": []},
    )

    assert provider.detail_url_for_entry(entry) is None
