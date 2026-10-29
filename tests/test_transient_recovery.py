import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlencode

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from tests.test_runner_cnvd_session import FakeCNVDSession
from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import Checkpoint, ScraperRunner
from vuln_scraper.scrapers.cnvd.provider import CNVDProvider
from vuln_scraper.scrapers.nvd.provider import NvdProvider


@asynccontextmanager
async def mock_client(respond, *, retries=0):
    def build(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(respond))

    with patch.object(ScraperClient, "_build_http_client", build):
        async with ScraperClient(delay=0, retries=retries, backoff_jitter=0) as client:
            with patch("vuln_scraper.client.asyncio.sleep", new_callable=AsyncMock) as sleep:
                yield client, sleep


@pytest.mark.parametrize("method,status", [("html", 504), ("get_json", 503), ("post_json", 503), ("request_json", 429)])
def test_transient_responses_honor_retry_after_and_recover(method, status):
    calls = []

    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(status, headers={"Retry-After": "60"})
        return httpx.Response(200, json={"ok": True})

    async def run():
        async with mock_client(respond, retries=1) as (client, sleep):
            if method == "html":
                result = await client.get_html("https://example.test/advisory")
            elif method == "request_json":
                result = await client.request_json("POST", "https://example.test/api", data={"x": "y"})
            else:
                result = await getattr(client, method)("https://example.test/api")
            assert result.status_code == 200
            assert sleep.await_args.args[0] == 60

    asyncio.run(run())
    assert len(calls) == 2


def test_retry_after_http_date_is_respected():
    calls = []
    retry_at = datetime.now(UTC) + timedelta(seconds=90)

    def respond(request):
        calls.append(request)
        return httpx.Response(503, headers={"Retry-After": format_datetime(retry_at)}) if len(calls) == 1 else httpx.Response(200, json={})

    async def run():
        async with mock_client(respond, retries=1) as (client, sleep):
            await client.get_json("https://example.test/api")
            assert 85 <= sleep.await_args.args[0] <= 90

    asyncio.run(run())


@pytest.mark.parametrize("header", ["invalid", "NaN", "-10"])
def test_invalid_retry_after_uses_normal_backoff(header):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(504, headers={"Retry-After": header}) if len(calls) == 1 else httpx.Response(200, text="ok")

    async def run():
        async with mock_client(respond, retries=1) as (client, sleep):
            await client.get_html("https://example.test/advisory")
            assert sleep.await_args.args[0] == 1

    asyncio.run(run())


@pytest.mark.parametrize("status,attempts", [(403, 1), (503, 3), (504, 3)])
def test_exhausted_status_is_preserved_and_attempts_are_bounded(status, attempts):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(status)

    async def run():
        async with mock_client(respond, retries=2) as (client, sleep):
            with pytest.raises(FetchError) as exc:
                await client.get_json("https://example.test/api")
            assert exc.value.status_code == status
            assert sleep.await_count == attempts - 1

    asyncio.run(run())
    assert len(calls) == attempts


def settings_for(tmp_path, *, limit=1):
    return ScraperSettings(
        data_dir=tmp_path, limit=limit, mongo_enabled=True, mongo_collection="news",
        mongo_config_file=None, scrapers_config_file=None, mongo_conflict="overwrite",
        request_delay=0, retries=0, concurrency=1, error_log=None,
    )


def test_cnvd_gateway_failure_does_not_overwrite_full_record_and_is_recovered_next_run(tmp_path):
    key = "cnvd:2026-42794"
    original = {"_id": key, "source": {"provider": "cnvd"}, "title": "Previous full record", "details": {"description": "Keep this"}}
    collection = FakeMongoCollection({key: original.copy()})
    settings = settings_for(tmp_path)
    list_html = '<table><tr><td><a href="/flaw/show/CNVD-2026-42794">Product 漏洞</a></td><td>高</td><td>2026-10-29</td></tr></table>'
    detail_html = (Path(__file__).parent / "scrapers/cnvd/fixtures/detail.html").read_text().replace("2026-21550", "2026-42794")

    def failing(request):
        return httpx.Response(200, text=list_html) if request.url.path == "/flaw/list" else httpx.Response(504)

    async def first_run():
        async with mock_client(failing) as (client, _):
            return await ScraperRunner(settings, provider=CNVDProvider(), mongo_client_factory=fake_mongo_factory(collection))._run_with_client(client)

    first = asyncio.run(first_run())
    assert first["result_count"] == 0
    assert collection.documents[key] == original
    assert first["failed"][0]["status_code"] == 504
    checkpoint_path = tmp_path / "checkpoint.json"
    assert key in Checkpoint.load(checkpoint_path).failed

    recovered_requests = []

    def recovered(request):
        recovered_requests.append(str(request.url))
        assert request.url.path == "/flaw/show/CNVD-2026-42794"
        return httpx.Response(200, text=detail_html)

    async def second_run():
        async with mock_client(recovered) as (client, _):
            runner = ScraperRunner(
                settings, provider=CNVDProvider(), mongo_client_factory=fake_mongo_factory(collection),
                updated_since=datetime(2026, 10, 30, tzinfo=UTC),
            )
            return await runner._run_with_client(client)

    second = asyncio.run(second_run())
    assert second["result_count"] == 1
    assert second["failed"] == []
    assert len(recovered_requests) == 1
    assert collection.documents[key]["details"]["description"] == "攻击者可利用该漏洞执行任意代码。"
    assert key not in Checkpoint.load(checkpoint_path).failed


def test_cnvd_jsl_response_reaches_session_refresh(tmp_path):
    requests_seen = []
    session = FakeCNVDSession()
    runner = ScraperRunner(settings_for(tmp_path), provider=CNVDProvider(), cnvd_session=session)

    def respond(request):
        requests_seen.append(request)
        if len(requests_seen) == 1:
            return httpx.Response(521, text='<script>document.cookie="__jsl_clearance_s=challenge";location.href="/";</script>')
        return httpx.Response(200, text="<table><tr><td>Valid advisory</td></tr></table>")

    async def run():
        async with mock_client(respond) as (client, _):
            result = await runner._fetch_provider_html(client, "https://www.cnvd.org.cn/flaw/show/CNVD-2026-42794")
            assert result.status_code == 200

    asyncio.run(run())
    assert session.authenticated == 1
    assert len(requests_seen) == 2


def cve(code, modified):
    return {"cve": {"id": code, "published": "2020-01-01T00:00:00.000", "lastModified": modified, "descriptions": [{"lang": "en", "value": code}]}}


def test_nvd_resumes_failed_window_and_scans_all_pages(tmp_path):
    window = {"lastModStartDate": "2026-10-21T00:05:08.000+00:00", "lastModEndDate": "2026-10-28T00:05:08.000+00:00"}
    failed_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({**window, "resultsPerPage": 2, "startIndex": 2})
    checkpoint = Checkpoint(failed={"nvd:LIST": {"identity": "nvd:LIST", "phase": "list", "url": failed_url, "error": f"Failed to fetch {failed_url}: HTTP 503"}})
    checkpoint.save(tmp_path / "checkpoint.json")
    collection = FakeMongoCollection()
    runner = ScraperRunner(settings_for(tmp_path, limit=5), provider=NvdProvider(page_size=2), mongo_client_factory=fake_mongo_factory(collection), updated_since=datetime(2026, 10, 29, tzinfo=UTC))
    offsets = []

    def respond(request):
        params = parse_qs(request.url.query.decode())
        assert params["lastModStartDate"] == [window["lastModStartDate"]]
        assert params["lastModEndDate"] == [window["lastModEndDate"]]
        offset = int(params["startIndex"][0])
        offsets.append(offset)
        if offset == 2:
            assert "nvd:LIST" in runner.checkpoint.failed
        records = [cve("CVE-2026-10001", "2026-10-22T00:00:00.000"), cve("CVE-2026-10002", "2026-10-27T00:00:00.000")] if offset == 0 else [cve("CVE-2026-10003", "2026-10-25T00:00:00.000")]
        return httpx.Response(200, json={"resultsPerPage": 2, "startIndex": offset, "totalResults": 3, "vulnerabilities": records})

    async def run():
        async with mock_client(respond) as (client, _):
            return await runner._run_with_client(client)

    output = asyncio.run(run())
    assert offsets == [0, 2]
    assert output["result_count"] == 3
    assert output["failed"] == []
    assert "nvd:LIST" not in Checkpoint.load(tmp_path / "checkpoint.json").failed


def test_nvd_does_not_stop_at_first_older_modified_record(tmp_path):
    collection = FakeMongoCollection()
    runner = ScraperRunner(settings_for(tmp_path, limit=5), provider=NvdProvider(), mongo_client_factory=fake_mongo_factory(collection), updated_since=datetime(2026, 10, 28, tzinfo=UTC))

    def respond(request):
        return httpx.Response(200, json={"resultsPerPage": 200, "totalResults": 2, "vulnerabilities": [cve("CVE-2026-10001", "2026-10-22T00:00:00.000"), cve("CVE-2026-10002", "2026-10-29T00:00:00.000")]})

    async def run():
        async with mock_client(respond) as (client, _):
            return await runner._run_with_client(client)

    output = asyncio.run(run())
    assert [item["code"] for item in output["vulnerabilities"]] == ["CVE-2026-10002"]
