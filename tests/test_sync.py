from __future__ import annotations

import asyncio

import pytest

from vuln_scraper.config import default_scrape_settings
from vuln_scraper.providers import HKCERTProvider
from vuln_scraper.sync import run_sync_cycle


def test_run_sync_cycle_calls_each_provider(monkeypatch) -> None:
    calls: list[str] = []
    collections: list[str | None] = []
    browser_fallbacks: list[bool] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None) -> None:
            self.provider = provider or HKCERTProvider()
            self.settings = settings.normalized()

        async def run(self):
            calls.append(self.provider.key)
            collections.append(self.settings.mongo_collection)
            browser_fallbacks.append(self.settings.browser_fallback)
            return {
                "vulnerabilities": [{"details": {self.provider.key: {}}}],
                "mongo_sync": {
                    "inserted": 1,
                    "overwritten": 0,
                    "skipped": 0,
                    "conflicts": 0,
                },
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("vuln_scraper.sync.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.sync.asyncio.run", fake_asyncio_run)

    run_sync_cycle(default_scrape_settings())

    assert calls == [
        "avd",
        "hkcert",
        "cve",
        "cisco",
        "zeroday",
        "govcert",
        "huawei_sa",
        "paloalto",
        "qianxin",
        "ransomwarelive",
        "infosec",
        "splunk",
        "hikvision",
        "cnnvd",
        "cnvd",
        "juniper",
    ]
    assert collections == [
        "avd",
        "hkcert",
        "cve",
        "cisco",
        "zeroday",
        "govcert",
        "huawei_sa",
        "paloalto",
        "qianxin",
        "ransomwarelive",
        "infosec",
        "splunk",
        "hikvision",
        "cnnvd",
        "cnvd",
        "juniper",
    ]
    assert browser_fallbacks == [
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        True,
        False,
        False,
        True,
    ]


def test_run_sync_cycle_can_include_manual_verification_provider(monkeypatch) -> None:
    calls: list[str] = []
    browser_fallbacks: list[bool] = []
    browser_headless_values: list[bool] = []
    concurrencies: list[int] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None) -> None:
            self.provider = provider or HKCERTProvider()
            self.settings = settings.normalized()

        async def run(self):
            calls.append(self.provider.key)
            browser_fallbacks.append(self.settings.browser_fallback)
            browser_headless_values.append(self.settings.browser_headless)
            concurrencies.append(self.settings.concurrency)
            return {
                "vulnerabilities": [{"details": {self.provider.key: {}}}],
                "mongo_sync": {
                    "inserted": 1,
                    "overwritten": 0,
                    "skipped": 0,
                    "conflicts": 0,
                },
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("vuln_scraper.sync.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.sync.asyncio.run", fake_asyncio_run)

    run_sync_cycle(default_scrape_settings(), include_manual_verification=True)

    cnvd_index = calls.index("cnvd")
    assert "cnvd" in calls
    assert browser_fallbacks[cnvd_index] is False
    assert browser_headless_values[cnvd_index] is True
    assert concurrencies[cnvd_index] == 1
