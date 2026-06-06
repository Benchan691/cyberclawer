from __future__ import annotations

import asyncio

import pytest

from vuln_scraper.catch_up import no_progress, provider_caught_up, run_catch_up_cycle
from vuln_scraper.config import default_scrape_settings
from vuln_scraper.providers import HKCERTProvider, ZeroDayProvider


def test_provider_caught_up_on_overlap() -> None:
    assert provider_caught_up({"stop_reason": "overlap"})
    assert not provider_caught_up({"stop_reason": "limit", "result_count": 10})


def test_provider_caught_up_cve_empty_run() -> None:
    assert provider_caught_up(
        {
            "source": {"provider": "cve"},
            "result_count": 0,
            "mongo_sync": {"inserted": 0},
            "stop_reason": "limit",
        }
    )


def test_no_progress_on_empty_result() -> None:
    assert no_progress({"result_count": 0, "mongo_sync": {}})
    assert not no_progress({"result_count": 0, "mongo_sync": {"deleted": 1}})
    assert not no_progress({"stop_reason": "overlap", "result_count": 0})


def test_run_catch_up_cycle_stops_on_overlap(monkeypatch) -> None:
    calls: list[str] = []
    outputs = [
        {
            "stop_reason": "limit",
            "result_count": 5,
            "vulnerabilities": [{"details": {"hkcert": {}}}],
            "mongo_sync": {"inserted": 5},
        },
        {
            "stop_reason": "overlap",
            "result_count": 0,
            "vulnerabilities": [],
            "mongo_sync": {"inserted": 0, "skipped": 2},
        },
    ]

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None) -> None:
            self.provider = provider or HKCERTProvider()
            assert stop_on_first_known is True

        async def run(self):
            output = outputs[min(len(calls), len(outputs) - 1)]
            calls.append(self.provider.key)
            return output

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("vuln_scraper.catch_up.all_providers", lambda: [HKCERTProvider()])
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings(), max_runs_per_provider=10)

    assert calls == ["hkcert", "hkcert"]


def test_run_catch_up_cycle_advances_through_providers(monkeypatch) -> None:
    calls: list[str] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None) -> None:
            self.provider = provider

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "overlap",
                "result_count": 0,
                "vulnerabilities": [],
                "mongo_sync": {"inserted": 0},
                "source": {"provider": self.provider.key},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(
        "vuln_scraper.catch_up.all_providers",
        lambda: [HKCERTProvider(), ZeroDayProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings())

    assert calls == ["hkcert", "zeroday"]


def test_run_catch_up_cycle_respects_max_runs(monkeypatch) -> None:
    calls: list[str] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None) -> None:
            self.provider = provider or HKCERTProvider()

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "limit",
                "result_count": 1,
                "vulnerabilities": [{"details": {"hkcert": {}}}],
                "mongo_sync": {"inserted": 1},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("vuln_scraper.catch_up.all_providers", lambda: [HKCERTProvider()])
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings(), max_runs_per_provider=2)

    assert calls == ["hkcert", "hkcert"]
