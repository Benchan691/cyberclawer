import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from tests.test_runner import FakeMongoCollection, fake_mongo_factory
from vuln_scraper.client import FetchError, ScraperClient
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.schema_v2 import validate_v2_document
from vuln_scraper.scrapers.hkcert.provider import HKCERTProvider
from vuln_scraper.sync_state import SyncContext


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("xml", [
    "<rss>",
    "<html><body>Temporarily unavailable</body></html>",
    "<rss><channel><item><title>Blog</title><link>https://www.hkcert.org/blog/example</link></item></channel></rss>",
])
def test_hkcert_reports_invalid_rss_as_a_list_failure(xml: str) -> None:
    with pytest.raises(FetchError, match="Invalid HKCERT security bulletin feed"):
        HKCERTProvider().parse_list(xml, page=1)


def test_hkcert_syncs_bulletin_edits_even_when_rss_stays_the_same(tmp_path) -> None:
    collection = FakeMongoCollection()
    urls: list[str] = []
    slug = "android-multiple-vulnerabilities_20260601"
    feed_url = "https://www.hkcert.org/getrss/security-bulletin"
    detail_url = f"https://www.hkcert.org/security-bulletin/{slug}"
    rss = (FIXTURES / "list.xml").read_text(encoding="utf-8")
    detail = (FIXTURES / "detail.html").read_text(encoding="utf-8")
    now = datetime(2026, 6, 2, 3, tzinfo=UTC)

    def respond(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        urls.append(url)
        if url == feed_url:
            return httpx.Response(200, text=rss, headers={"Content-Type": "application/rss+xml"})
        assert url == detail_url
        return httpx.Response(200, text=detail, headers={"Content-Type": "text/html"})

    settings = ScraperSettings(
        data_dir=tmp_path, limit=1, mongo_enabled=True, mongo_collection="news",
        mongo_config_file=None, scrapers_config_file=None, mongo_conflict="overwrite",
        request_delay=0, retries=0, error_log=None,
    )

    async def run(at: datetime) -> dict:
        async with ScraperClient(delay=0, retries=0) as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            runner = ScraperRunner(
                settings, provider=HKCERTProvider(),
                mongo_client_factory=fake_mongo_factory(collection),
                sync_context=SyncContext(until=at),
            )
            return await runner._run_with_client(client)

    output = asyncio.run(run(now))

    assert urls == [feed_url, detail_url]
    assert output["failed"] == []
    assert output["mongo_sync"]["inserted"] == 1
    document = collection.documents[f"hkcert:{slug}"]
    validate_v2_document(document, "news")
    assert document["source"]["detail_url"] == detail_url
    assert document["published_at"] == datetime(2026, 5, 31, 16, tzinfo=UTC)
    assert document["updated_at"] == datetime(2026, 6, 1, 16, tzinfo=UTC)
    assert document["severity"] == "Medium"
    assert document["cve_ids"] == ["CVE-2025-48595", "CVE-2025-48633"]
    assert "Apply fixes issued by the vendor" in document["details"]["solutions"]

    urls.clear()
    detail = detail.replace("Last Update Date: 2 Jun 2026", "Last Update Date: 3 Jun 2026")
    updated = asyncio.run(run(now + timedelta(days=1)))

    assert urls == [feed_url, detail_url]
    assert updated["failed"] == []
    assert updated["mongo_sync"]["overwritten"] == 1
    assert collection.documents[f"hkcert:{slug}"]["updated_at"] == datetime(2026, 6, 2, 16, tzinfo=UTC)
