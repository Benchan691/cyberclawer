from urllib.parse import parse_qs, urlparse

from vuln_scraper.providers import GitHubAdvisoryProvider, get_provider, provider_keys
from vuln_scraper.scrapers.github_advisory.config import DETAIL_URL, LIST_URL


def test_github_advisory_provider_registry_and_defaults() -> None:
    provider = get_provider("github_advisory")

    assert isinstance(provider, GitHubAdvisoryProvider)
    assert "github_advisory" in provider_keys()
    assert provider.content_type == "json"
    assert not provider.browser_fallback
    assert provider.default_mongo_collection == "github_advisory"
    assert provider.stop_on_first_known


def test_github_advisory_provider_urls_and_query() -> None:
    provider = GitHubAdvisoryProvider()

    url = provider.list_url(2)
    parsed = urlparse(url)

    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == LIST_URL
    assert parse_qs(parsed.query) == {
        "type": ["reviewed"],
        "sort": ["published"],
        "direction": ["desc"],
        "per_page": ["100"],
        "page": ["2"],
    }
    assert provider.detail_url("GHSA-abcd-1234-efgh") == f"{DETAIL_URL}/GHSA-abcd-1234-efgh"


def test_github_advisory_provider_headers_without_token(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    assert GitHubAdvisoryProvider().request_headers() == {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }


def test_github_advisory_provider_headers_with_token(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", " test-token ")

    assert GitHubAdvisoryProvider().request_headers() == {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Authorization": "Bearer test-token",
    }
