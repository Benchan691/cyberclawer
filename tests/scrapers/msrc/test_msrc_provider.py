from urllib.parse import unquote, urlparse

from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.scrapers import MSRCProvider, get_provider, provider_keys
from vuln_scraper.scrapers.msrc.config import DETAIL_URL, LIST_URL


def test_msrc_provider_registry_and_defaults() -> None:
    provider = get_provider("msrc")

    assert isinstance(provider, MSRCProvider)
    assert "msrc" in provider_keys()
    assert provider.content_type == "json"
    assert not provider.browser_fallback
    assert provider.default_mongo_collection == "msrc"
    assert not provider.stop_on_first_known


def test_msrc_provider_urls_and_headers() -> None:
    provider = MSRCProvider()

    parsed = urlparse(provider.list_url(1))
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == LIST_URL
    assert unquote(parsed.query) == "$orderby=currentReleaseDate desc"
    assert provider.detail_url("MSRC-2026-Jun") == f"{DETAIL_URL}/2026-Jun"
    assert provider.request_headers() == {"Accept": "application/json"}


def test_msrc_provider_detail_url_prefers_embedded_cvrf_url() -> None:
    provider = MSRCProvider()
    entry = ListEntry(
        identity=VulnerabilityId(type="MSRC", code="2026-Jun"),
        title="June 2026 Security Updates",
        vuln_type=None,
        disclosure_date=None,
        status=None,
        provider="msrc",
        embedded_detail={"cvrf_url": "https://example.test/cvrf/2026-Jun"},
    )

    assert provider.detail_url_for_entry(entry) == "https://example.test/cvrf/2026-Jun"
