from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.providers import CNNVDProvider, get_provider, provider_keys
from vuln_scraper.scrapers.cnnvd.config import DETAIL_API_URL, LIST_API_URL, SOURCE_URL


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
        "pageIndex": 2,
        "pageSize": 50,
        "keyword": "",
        "hazardLevel": "",
        "vulType": "",
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
            "cnnvdCode": "CNNVD-202606-1911",
            "cveCode": "CVE-2026-11628",
            "vulType": "0",
        },
    )
    requests = provider.detail_json_requests(entry, detail_url=provider.detail_url(entry.display_id))

    assert [request["url"] for request in requests] == [DETAIL_API_URL] * 3
    assert [request["json"] for request in requests] == [
        {
            "id": "record-1911",
            "cnnvdCode": "CNNVD-202606-1911",
            "cveCode": "CVE-2026-11628",
            "vulType": "0",
        },
        {"id": "record-1911", "vulType": "0"},
        {"cnnvdCode": "CNNVD-202606-1911", "vulType": "0"},
    ]
