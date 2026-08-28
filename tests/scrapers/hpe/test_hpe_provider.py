import asyncio
from pathlib import Path

from vuln_scraper.client import FetchResult
from vuln_scraper.config import ScraperSettings
from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.mongo import build_mongo_document
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers import HPEProvider, get_provider, provider_keys
from vuln_scraper.scrapers.hpe.config import DOCUMENT_API_URL, LIST_URL, SOURCE_URL


FIXTURES = Path(__file__).parent / "fixtures"


def test_hpe_provider_registry_and_defaults() -> None:
    provider = get_provider("hpe")

    assert isinstance(provider, HPEProvider)
    assert "hpe" in provider_keys()
    assert provider.source_url == SOURCE_URL
    assert provider.content_type == "html"
    assert not provider.browser_fallback
    assert not provider.always_use_browser
    assert provider.default_request_delay == 1.0
    assert provider.stop_on_first_known
    assert provider.default_mongo_collection == "hpe"


def test_hpe_provider_urls_use_rss_for_index_and_document_api_for_details() -> None:
    provider = HPEProvider()

    assert provider.list_url(1) == LIST_URL
    assert provider.list_url(99) == LIST_URL
    assert provider.detail_url("HPE-hpesbnw05119en_us") == (
        f"{DOCUMENT_API_URL}/hpesbnw05119en_us"
    )
    assert provider.detail_url("hpesbnw05119en_us") == (
        f"{DOCUMENT_API_URL}/hpesbnw05119en_us"
    )


def test_hpe_provider_detail_url_for_entry_uses_doc_id_not_doc_display_link() -> None:
    provider = HPEProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="HPE", code="hpesbnw05119en_us"),
        title="HPE bulletin",
        vuln_type="Security Bulletin",
        disclosure_date="2026-08-07",
        status="Critical",
        provider="hpe",
        embedded_detail={
            "doc_id": "hpesbnw05119en_us",
            "doc_display_url": "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05119en_us",
        },
    )

    assert provider.detail_url_for_entry(entry) == f"{DOCUMENT_API_URL}/hpesbnw05119en_us"


def test_hpe_record_is_accepted_by_schema_v2() -> None:
    record = {
        "type": "hpe",
        "code": "hpesbnw05119en_us",
        "title": "HPE bulletin",
        "status": "Critical",
        "disclosure_date": "2026-08-07",
        "details": {
            "hpe": {
                "doc_id": "hpesbnw05119en_us",
                "title": "HPE bulletin",
                "release_date": "2026-08-07",
                "severity": "Critical",
                "cve_ids": ["CVE-2026-54763", "CVE-2026-33377"],
            }
        },
    }

    document = build_mongo_document(
        record,
        {"scraped_at": "2026-08-28T09:43:19Z"},
    )

    assert document["_id"] == "hpe:hpesbnw05119en_us"
    assert document["cve_ids"] == ["CVE-2026-54763", "CVE-2026-33377"]


class _FakeHPEClient:
    def __init__(self) -> None:
        self.html_urls: list[str] = []
        self.json_calls = 0

    async def get_html(self, url: str) -> FetchResult:
        self.html_urls.append(url)
        if url == LIST_URL:
            html = (FIXTURES / "list.html").read_text(encoding="utf-8")
        elif url.startswith(f"{DOCUMENT_API_URL}/"):
            html = (FIXTURES / "detail.html").read_text(encoding="utf-8")
        else:
            raise AssertionError(f"unexpected HPE URL: {url}")
        return FetchResult(html=html, status_code=200, url=url)

    async def request_json(self, *args, **kwargs):
        self.json_calls += 1
        raise AssertionError("HPE must not use a JSON or browser fetch path")


def test_hpe_runner_fetches_rss_and_api_over_http_only(tmp_path) -> None:
    client = _FakeHPEClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "hpe.json",
        checkpoint_file=tmp_path / "hpe_checkpoint.json",
        limit=1,
        mongo_enabled=False,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(ScraperRunner(settings, provider=HPEProvider())._run_with_client(client))

    assert client.html_urls == [LIST_URL, f"{DOCUMENT_API_URL}/hpesbnw05119en_us"]
    assert client.json_calls == 0
    record = output["vulnerabilities"][0]
    assert record["type"] == "hpe"
    assert record["code"] == "hpesbnw05119en_us"
    assert record["cve_codes"] == ["2026-54763", "2026-33377"]
    assert record["source"]["detail_url"] == f"{DOCUMENT_API_URL}/hpesbnw05119en_us"
    assert record["details"]["hpe"]["doc_display_url"] == (
        "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05119en_us&docLocale=en_US"
    )
