from vuln_scraper.models import ListEntry, VulnerabilityId
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


def test_avd_provider_uses_list_detail_link_when_available() -> None:
    provider = AVDProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="AVD", code="2026-10001"),
        title="Product RCE",
        vuln_type="CWE-78",
        disclosure_date="2026-01-01",
        status="CVE PoC",
        provider="avd",
        embedded_detail={
            "reference_links": ["https://avd.aliyun.com/detail?id=AVD-2026-10001&foo=1"]
        },
    )

    assert (
        provider.detail_url_for_entry(entry)
        == "https://avd.aliyun.com/detail?id=AVD-2026-10001&foo=1"
    )


def test_avd_provider_falls_back_to_detail_url_without_reference_links() -> None:
    provider = AVDProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="AVD", code="2026-10001"),
        title="Product RCE",
        vuln_type=None,
        disclosure_date=None,
        status=None,
        provider="avd",
        embedded_detail={"reference_links": []},
    )

    assert provider.detail_url_for_entry(entry) == "https://avd.aliyun.com/detail?id=AVD-2026-10001"


def test_avd_provider_request_headers_include_env_cookie(monkeypatch) -> None:
    monkeypatch.setenv("AVD_COOKIE", "aliyungf_tc=token; acw_tc=clearance")

    headers = AVDProvider().request_headers()

    assert headers["Cookie"] == "aliyungf_tc=token; acw_tc=clearance"
    assert "User-Agent" in headers
