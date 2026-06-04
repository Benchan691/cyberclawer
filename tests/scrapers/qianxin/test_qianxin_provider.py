from vuln_scraper.providers import QianxinProvider, get_provider, provider_keys
from vuln_scraper.scrapers.qianxin.config import DEFAULT_PAGE_SIZE, DETAIL_API_URL, LIST_API_URL


def test_qianxin_provider_registry_and_defaults() -> None:
    provider = get_provider("qianxin")

    assert isinstance(provider, QianxinProvider)
    assert "qianxin" in provider_keys()
    assert provider.content_type == "json"
    assert not provider.browser_fallback
    assert provider.default_mongo_collection == "qianxin"
    assert provider.stop_on_first_known


def test_qianxin_provider_urls_and_requests() -> None:
    provider = QianxinProvider()

    assert provider.list_url(1) == LIST_API_URL
    assert provider.detail_url("QIANXIN-1868") == "https://ti.qianxin.com/vulnerability/notice-detail/1868?type=risk"

    list_request = provider.list_json_request(2)
    assert list_request["method"] == "POST"
    assert list_request["url"] == LIST_API_URL
    assert list_request["headers"]["lang"] == "zh-CN"
    assert list_request["json"] == {
        "page_no": 2,
        "page_size": DEFAULT_PAGE_SIZE,
        "category": "风险通告",
    }

    class Entry:
        class Identity:
            code = "1868"

        identity = Identity()

    detail_request = provider.detail_json_request(Entry(), detail_url=provider.detail_url("QIANXIN-1868"))
    assert detail_request["method"] == "GET"
    assert detail_request["url"] == f"{DETAIL_API_URL}?id=1868"
    assert detail_request["headers"]["Referer"] == "https://ti.qianxin.com/vulnerability/notice-detail/1868?type=risk"
