import asyncio
import json
from pathlib import Path

import httpx
import pytest

from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers.qianxin.config import DETAIL_API_URL, HOSTNAME, LIST_API_URL
from vuln_scraper.scrapers.qianxin.provider import QianxinProvider


FIXTURES = Path(__file__).parent / "fixtures"
FALLBACK_IP = "93.184.216.34"
DNS_ERROR = "[Errno -2] Name or service not known"


def mock_http(monkeypatch, respond) -> None:
    client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client(
        transport=httpx.MockTransport(respond), **kwargs,
    ))


def test_runner_recovers_qianxin_list_and_detail_after_dns_failure(monkeypatch, tmp_path) -> None:
    requests = []

    def respond(request):
        requests.append((request.method, request.url.host))
        if request.url.host == HOSTNAME:
            raise httpx.ConnectError(DNS_ERROR)
        if request.url.host == "dns.google":
            assert request.url.params["name"] == HOSTNAME
            assert request.url.params["type"] == "A"
            assert request.url.params["edns_client_subnet"] == "114.114.114.0/24"
            return httpx.Response(200, json={"Status": 0, "Answer": [
                {"type": 5, "data": "ti.qianxincdn.com."},
                {"type": 1, "data": "127.0.0.1", "TTL": 60},
                {"type": 1, "data": FALLBACK_IP, "TTL": 60},
            ]})

        assert request.url.host == FALLBACK_IP
        assert request.headers["Host"] == HOSTNAME
        assert request.extensions["sni_hostname"] == HOSTNAME
        if request.url.path == httpx.URL(LIST_API_URL).path:
            assert request.method == "POST"
            assert json.loads(request.content) == {"page_no": 1, "page_size": 10, "category": "风险通告"}
            fixture = "list.json"
        else:
            assert request.method == "GET"
            assert request.url.path == httpx.URL(DETAIL_API_URL).path
            assert request.url.params["id"] == "1868"
            fixture = "detail.json"
        return httpx.Response(200, json=json.loads((FIXTURES / fixture).read_text(encoding="utf-8")))

    mock_http(monkeypatch, respond)
    config = tmp_path / "scrapers.toml"
    config.write_text("[scrapers.email]\nenabled = false\n", encoding="utf-8")
    settings = ScraperSettings(data_dir=tmp_path, limit=1, request_delay=0, retries=0,
        scrapers_config_file=config, mongo_enabled=False,
        output_file=tmp_path / "result.json", checkpoint_file=tmp_path / "checkpoint.json")

    output = asyncio.run(ScraperRunner(settings, provider=QianxinProvider()).run())

    assert not output["failed"]
    record, = output["vulnerabilities"]
    assert record["details"]["qianxin"]["article_id"] == "1868"
    assert record["source"]["detail_url"] == f"https://{HOSTNAME}/vulnerability/notice-detail/1868?type=risk"
    assert requests == [("POST", HOSTNAME), ("GET", "dns.google"), ("POST", FALLBACK_IP),
                        ("GET", HOSTNAME), ("GET", FALLBACK_IP)]


@pytest.mark.parametrize("message", ["Connection refused", "certificate verify failed"])
def test_qianxin_does_not_use_dns_fallback_for_other_connection_failures(monkeypatch, message) -> None:
    def respond(request):
        assert str(request.url) == LIST_API_URL
        raise httpx.ConnectError(message)

    mock_http(monkeypatch, respond)

    async def run():
        async with ScraperClient(delay=0, retries=0, dns_fallback=QianxinProvider().dns_fallback) as client:
            with pytest.raises(FetchError, match=message):
                await client.post_json(LIST_API_URL, json={})

    asyncio.run(run())
