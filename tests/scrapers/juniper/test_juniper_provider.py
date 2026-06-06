import asyncio
from typing import Any

import pytest

from vuln_scraper.config import ScraperSettings
from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.providers import JuniperProvider, get_provider, provider_keys
from vuln_scraper.runner import ScraperRunner


def test_juniper_provider_registry_and_defaults() -> None:
    provider = get_provider("juniper")

    assert isinstance(provider, JuniperProvider)
    assert "juniper" in provider_keys()
    assert provider.content_type == "json"
    assert not provider.browser_fallback
    assert not provider.always_use_browser
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


def test_juniper_list_json_request_uses_coveo_facets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vuln_scraper.scrapers.juniper.provider.get_coveo_config",
        lambda page_uri="/s/global-search/@uri": {
            "organizationId": "junipernetworks",
            "accessToken": "test-token",
        },
    )
    provider = JuniperProvider()
    request = provider.list_json_request(2)

    assert request["method"] == "POST"
    assert "coveo.com" in request["url"]
    assert request["headers"]["Authorization"] == "Bearer test-token"
    assert request["json"]["firstResult"] == 10
    assert request["json"]["q"] == '@sfrecordtypename=="Security Advisories"'
    assert request["json"]["facetFilters"] == [
        {"field": "@primarysourcename", "values": ["Knowledge"]},
        {"field": "@articletype", "values": ["Security Advisories"]},
    ]


class _FakeJSONResult:
    def __init__(self, data: dict, url: str) -> None:
        self.data = data
        self.url = url


class _FakeJuniperClient:
    def __init__(self) -> None:
        self.detail_slugs_seen: list[str] = []

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Any = None,
        json_body: Any = None,
        data: Any = None,
    ) -> _FakeJSONResult:
        if json_body and json_body.get("fieldsToInclude"):
            slug = "JSA93456"
            self.detail_slugs_seen.append(slug)
            return _FakeJSONResult(_detail_payload(slug), url)
        return _FakeJSONResult(_list_payload(), url)


def _list_payload() -> dict:
    return {
        "totalCount": 2,
        "results": [
            {
                "title": "JSA93456: Junos OS: New J-Web issue",
                "raw": {
                    "sfcec_documentid__c": "JSA93456",
                    "sftitle": "JSA93456: Junos OS: New J-Web issue",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93456",
                    "sfurlname": "JSA93456",
                },
            },
            {
                "title": "JSA93455: Known Junos issue",
                "raw": {
                    "sfcec_documentid__c": "JSA93455",
                    "sftitle": "JSA93455: Known Junos issue",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-22",
                    "sfcustomer_url__c": "https://supportportal.juniper.net/s/article/JSA93455",
                },
            },
        ],
    }


def _detail_payload(slug: str) -> dict:
    return {
        "results": [
            {
                "title": f"{slug}: Junos OS Security Advisory",
                "raw": {
                    "sfcec_documentid__c": slug,
                    "sftitle": f"{slug}: Junos OS Security Advisory",
                    "sfrecordtypename": "Security Advisories",
                    "sflastpublisheddate": "2026-05-29",
                    "sfcustomer_url__c": f"https://supportportal.juniper.net/s/article/{slug}",
                    "sfcec_problem__c": "Detail includes CVE-2026-55555.",
                    "sfcec_product_affected__c": "Junos OS",
                    "sfcec_solution__c": "Upgrade Junos OS.",
                },
            }
        ]
    }


def test_juniper_runner_uses_coveo_without_browser(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vuln_scraper.scrapers.juniper.provider.get_coveo_config",
        lambda page_uri="/s/global-search/@uri": {
            "organizationId": "junipernetworks",
            "accessToken": "test-token",
        },
    )
    client = _FakeJuniperClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "juniper.json",
        checkpoint_file=tmp_path / "juniper_checkpoint.json",
        limit=1,
        mongo_enabled=False,
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        ScraperRunner(settings, provider=JuniperProvider())._run_with_client(client)
    )

    ids = [f"{record['type']}:{record['code']}" for record in output["vulnerabilities"]]
    assert ids == ["juniper:JSA93456"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-55555"
    assert client.detail_slugs_seen == ["JSA93456"]
