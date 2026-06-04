import asyncio
from pathlib import Path
from unittest.mock import patch

from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner
from vuln_scraper.scrapers.cnvd import CNVDProvider
from tests.test_runner import FakeCNVDClient, identities


class FakeCNVDSession:
    def __init__(self, cookie_path: Path | None = None) -> None:
        self.cookie_path = cookie_path
        self.authenticated = 0
        self._cookies: list[dict[str, str]] = []

    @classmethod
    def for_data_dir(
        cls,
        data_dir: Path,
        *,
        cookie_path: Path | None = None,
        max_retries: int = 50,
        retry_delay: float = 0.3,
    ) -> "FakeCNVDSession":
        del data_dir, max_retries, retry_delay
        return cls(cookie_path=cookie_path)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._cookies)

    def ensure_authenticated(self, *, refresh_cookies: bool = True, persist_cookies: bool = False) -> None:
        self.authenticated += 1
        self._cookies = [{"name": "__jsluid_s", "value": "x", "domain": "www.cnvd.org.cn", "path": "/"}]

    def cookies_for_httpx(self) -> list[dict[str, str]]:
        return list(self._cookies)


class FakeCNVDClientWithCookies(FakeCNVDClient):
    def __init__(self) -> None:
        super().__init__()
        self.cookies_injected = 0

    def inject_cookies(self, cookies: list[dict[str, str]]) -> None:
        self.cookies_injected += 1
        assert cookies


class PatchedScraperClient:
    def __init__(self, *args, **kwargs) -> None:
        self._client = FakeCNVDClientWithCookies()

    async def __aenter__(self) -> FakeCNVDClientWithCookies:
        return self._client

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


def test_cnvd_run_prepares_session_and_uses_http(tmp_path: Path) -> None:
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cnvd.json",
        checkpoint_file=tmp_path / "cnvd_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
        browser_fallback=True,
    )
    scraper = ScraperRunner(settings, provider=CNVDProvider())
    assert scraper.settings.browser_fallback is False

    preauth = FakeCNVDSession()
    preauth.ensure_authenticated()

    with patch("vuln_scraper.runner.ScraperClient", PatchedScraperClient):
        output = asyncio.run(
            ScraperRunner(settings, provider=CNVDProvider(), cnvd_session=preauth).run()
        )

    assert identities(output["vulnerabilities"]) == ["cnvd:2026-21550"]
