from vuln_scraper.providers import CNNVDProvider, get_provider, provider_keys
from vuln_scraper.scrapers.cnnvd.config import DETAIL_API_URL, LIST_API_URL


def test_cnnvd_provider_registry_and_defaults() -> None:
    provider = get_provider("cnnvd")

    assert isinstance(provider, CNNVDProvider)
    assert "cnnvd" in provider_keys()
    assert provider.content_type == "json"
    assert not provider.browser_fallback
    assert provider.default_mongo_collection == "cnnvd"
    assert provider.stop_on_first_known


def test_cnnvd_provider_urls_and_requests() -> None:
    provider = CNNVDProvider()

    assert provider.list_url(1) == LIST_API_URL
    assert provider.detail_url("CNNVD-abc123") == "https://www.cnnvd.org.cn/home/warn?warnId=abc123"

    list_request = provider.list_json_request(2)
    assert list_request["method"] == "POST"
    assert list_request["url"] == LIST_API_URL
    assert list_request["json"]["pageIndex"] == 2
    assert list_request["json"]["pageSize"] == 100

    class Entry:
        class Identity:
            code = "abc123"

        identity = Identity()

    detail_request = provider.detail_json_request(Entry(), detail_url=provider.detail_url("CNNVD-abc123"))
    assert detail_request["method"] == "POST"
    assert detail_request["url"] == DETAIL_API_URL
    assert detail_request["data"] == {"warnId": "abc123"}
