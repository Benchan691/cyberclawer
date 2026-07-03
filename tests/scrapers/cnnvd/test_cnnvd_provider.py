import asyncio

from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.scrapers import CNNVDProvider, get_provider, provider_keys
from vuln_scraper.scrapers.cnnvd.config import DETAIL_API_URL, LIST_API_URL, SIGN_API_URL, SOURCE_URL


class FakeJSONResult:
    def __init__(self, data):
        self.data = data


class FakeClient:
    def __init__(self) -> None:
        self.requests = []

    async def request_json(self, method: str, url: str, *, headers=None, json_body=None, data=None):
        self.requests.append({"method": method, "url": url, "headers": headers, "json": json_body})
        return FakeJSONResult({"code": 200, "data": "test-signature"})


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
    assert provider.detail_url("CNNVD-202606-1911") == SOURCE_URL

    list_request = provider.list_json_request(2)
    assert list_request["method"] == "POST"
    assert list_request["url"] == LIST_API_URL
    assert list_request["json"] == {
        "sortOrder": "desc",
        "sortField": "publishDate",
        "page": 2,
        "pageSize": 50,
    }

    entry = ListEntry(
        identity=VulnerabilityId(type="CNNVD", code="202606-1911"),
        title="Example",
        vuln_type="0",
        disclosure_date=None,
        status=None,
        provider="cnnvd",
        embedded_detail={
            "id": "record-1911",
            "cnnvdId": "CNNVD-202606-1911",
            "cveId": "CVE-2026-11628",
        },
    )
    requests = provider.detail_json_requests(entry, detail_url=provider.detail_url(entry.display_id))

    assert [request["url"] for request in requests] == [DETAIL_API_URL]
    assert [request["json"] for request in requests] == [{"id": "record-1911"}]


def test_cnnvd_provider_signs_json_requests() -> None:
    provider = CNNVDProvider()
    request = provider.list_json_request(1)
    signed = asyncio.run(provider.finalize_json_request(FakeClient(), request))

    assert signed["json"] == request["json"]
    assert signed["headers"]["X-Appid"]
    assert signed["headers"]["X-Timestamp"]
    assert len(signed["headers"]["X-Nonce"]) == 32
    assert signed["headers"]["X-Sign"] == "test-signature"

    client = FakeClient()
    asyncio.run(provider.finalize_json_request(client, request))
    sign_request = client.requests[0]
    assert sign_request["url"] == SIGN_API_URL
    assert sign_request["json"]["signStr"].startswith("POST/cnnvdweb/homePage/searchVul")
