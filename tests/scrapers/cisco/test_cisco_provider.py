import asyncio

import httpx
import pytest

from vuln_scraper.providers import CiscoProvider, get_provider, provider_keys
from vuln_scraper.scrapers.cisco import CiscoAuthError


def test_cisco_provider_urls_headers_and_registry(monkeypatch) -> None:
    monkeypatch.setenv("CISCO_OPENVULN_TOKEN", "secret-token")
    provider = CiscoProvider()

    assert "cisco" in provider_keys()
    assert get_provider("cisco").key == "cisco"
    assert provider.list_url(1) == "https://apix.cisco.com/security/advisories/v2/all?pageIndex=1&pageSize=100"
    assert provider.list_url(3) == "https://apix.cisco.com/security/advisories/v2/all?pageIndex=3&pageSize=100"
    assert (
        provider.detail_url("CISCO-cisco-sa-foo-123")
        == "https://apix.cisco.com/security/advisories/v2/advisory/cisco-sa-foo-123"
    )
    assert provider.request_headers() == {
        "Accept": "application/json",
        "Authorization": "Bearer secret-token",
    }
    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer secret-token",
    }
    assert provider.default_mongo_collection == "cisco"
    assert not provider.browser_fallback
    assert not provider.stop_on_first_known


def test_cisco_provider_fetches_and_caches_oauth_token(monkeypatch) -> None:
    monkeypatch.delenv("CISCO_OPENVULN_TOKEN", raising=False)
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_ID", "client-id")
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_SECRET", "client-secret")
    calls: list[tuple[str, str]] = []

    async def fake_fetch(self, client_id: str, client_secret: str) -> dict[str, object]:
        calls.append((client_id, client_secret))
        return {"access_token": "oauth-token", "expires_in": 3600}

    monkeypatch.setattr(CiscoProvider, "_fetch_access_token", fake_fetch)
    provider = CiscoProvider()

    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer oauth-token",
    }
    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer oauth-token",
    }
    assert calls == [("client-id", "client-secret")]


def test_cisco_provider_accepts_client_key_alias(monkeypatch) -> None:
    for name in (
        "CISCO_OPENVULN_TOKEN",
        "CISCO_OPENVULN_CLIENT_ID",
        "CISCO_CLIENT_ID",
        "CISCO_CLIENT_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_KEY", "client-key")
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_SECRET", "client-secret")
    calls: list[tuple[str, str]] = []

    async def fake_fetch(self, client_id: str, client_secret: str) -> dict[str, object]:
        calls.append((client_id, client_secret))
        return {"access_token": "oauth-token", "expires_in": 3600}

    monkeypatch.setattr(CiscoProvider, "_fetch_access_token", fake_fetch)

    assert asyncio.run(CiscoProvider().async_request_headers())["Authorization"] == "Bearer oauth-token"
    assert calls == [("client-key", "client-secret")]


def test_cisco_provider_token_request_uses_basic_auth(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeAsyncClient:
        def __init__(self, *, timeout) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def post(self, url, *, headers=None, data=None, auth=None):
            calls.append({"url": url, "headers": headers, "data": data, "auth": auth})
            return httpx.Response(
                200,
                json={"access_token": "token-from-cisco", "expires_in": 3600},
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr("vuln_scraper.scrapers.cisco.provider.httpx.AsyncClient", FakeAsyncClient)

    payload = asyncio.run(CiscoProvider()._fetch_access_token("client-key", "client-secret"))

    assert payload["access_token"] == "token-from-cisco"
    assert calls == [
        {
            "url": "https://id.cisco.com/oauth2/default/v1/token",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": {"grant_type": "client_credentials"},
            "auth": ("client-key", "client-secret"),
        }
    ]


def test_cisco_provider_missing_credentials_fails_before_api_request(monkeypatch) -> None:
    for name in (
        "CISCO_OPENVULN_TOKEN",
        "CISCO_OPENVULN_CLIENT_ID",
        "CISCO_OPENVULN_CLIENT_KEY",
        "CISCO_OPENVULN_CLIENT_SECRET",
        "CISCO_CLIENT_ID",
        "CISCO_CLIENT_KEY",
        "CISCO_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(CiscoAuthError, match="requires authentication"):
        asyncio.run(CiscoProvider().async_request_headers())
