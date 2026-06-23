from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from vuln_scraper.catch_up import (
    CATCH_UP_BATCH_SIZE,
    CATCH_UP_DEFAULT_LIMIT,
    no_progress,
    provider_caught_up,
    providers_for_catch_up,
    run_catch_up_cycle,
)
from vuln_scraper.config import default_scrape_settings
from vuln_scraper.scrapers import CVEProvider, HKCERTProvider, ZeroDayProvider, all_providers


def test_provider_caught_up_ignores_overlap() -> None:
    assert not provider_caught_up({"stop_reason": "overlap"})
    assert not provider_caught_up({"stop_reason": "limit", "result_count": 10})


def test_provider_caught_up_on_timestamp_boundary() -> None:
    assert provider_caught_up({"stop_reason": "timestamp_boundary"})


def test_no_progress_on_empty_result() -> None:
    assert no_progress({"result_count": 0, "mongo_sync": {}})
    assert not no_progress({"result_count": 0, "mongo_sync": {"deleted": 1}})
    assert no_progress({"stop_reason": "overlap", "result_count": 0})


def test_catch_up_default_limit_is_one_thousand() -> None:
    assert CATCH_UP_DEFAULT_LIMIT == 1000


def test_catch_up_default_batch_size_is_five() -> None:
    assert CATCH_UP_BATCH_SIZE == 5


def test_run_catch_up_cycle_uses_overwrite_conflict(monkeypatch) -> None:
    conflicts: list[str] = []
    updated_since_seen: list[object] = []

    class FakeScraper:
        def __init__(
            self,
            settings,
            *,
            provider=None,
            stop_on_first_known=None,
            stop_on_unchanged_content=False,
            updated_since=None,
        ) -> None:
            conflicts.append(settings.mongo_conflict)
            updated_since_seen.append(updated_since)
            self.provider = provider or HKCERTProvider()

        async def run(self):
            return {
                "stop_reason": "timestamp_boundary",
                "result_count": 0,
                "vulnerabilities": [],
                "mongo_sync": {"inserted": 0},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [HKCERTProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(
        replace(default_scrape_settings(limit=20), mongo_conflict="overwrite").normalized()
    )

    assert conflicts == ["overwrite"]
    assert updated_since_seen[0] is not None


def test_run_catch_up_cycle_runs_provider_once_for_timestamp_boundary(monkeypatch) -> None:
    calls: list[str] = []

    class FakeScraper:
        def __init__(
            self,
            settings,
            *,
            provider=None,
            stop_on_first_known=None,
            stop_on_unchanged_content=False,
            updated_since=None,
        ) -> None:
            self.provider = provider or HKCERTProvider()
            assert stop_on_unchanged_content is False
            assert updated_since is not None

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "timestamp_boundary",
                "result_count": 0,
                "vulnerabilities": [],
                "mongo_sync": {"inserted": 0, "skipped": 2},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [HKCERTProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings(), max_runs_per_provider=10)

    assert calls == ["hkcert"]


def test_run_catch_up_cycle_advances_through_providers(monkeypatch) -> None:
    calls: list[str] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None, stop_on_unchanged_content=False, updated_since=None) -> None:
            self.provider = provider

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "timestamp_boundary",
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
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [HKCERTProvider(), ZeroDayProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings())

    assert calls == ["hkcert", "zeroday"]


def test_run_catch_up_cycle_uses_one_timestamp_run(monkeypatch) -> None:
    calls: list[str] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None, stop_on_unchanged_content=False, updated_since=None) -> None:
            self.provider = provider or HKCERTProvider()
            assert updated_since is not None

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "timestamp_boundary",
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

    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [HKCERTProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings(), max_runs_per_provider=2)

    assert calls == ["hkcert"]


def test_run_catch_up_cycle_uses_per_provider_limit(monkeypatch) -> None:
    limits_seen: list[int] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None, stop_on_unchanged_content=False, updated_since=None) -> None:
            limits_seen.append(settings.limit)
            self.settings = settings
            self.provider = provider or HKCERTProvider()

        async def run(self):
            count = min(self.settings.limit, 10)
            return {
                "stop_reason": "limit",
                "result_count": count,
                "vulnerabilities": [{"details": {"hkcert": {}}}] * count,
                "mongo_sync": {"inserted": count},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [HKCERTProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(default_scrape_settings(limit=25), max_runs_per_provider=10, batch_size=5)

    assert limits_seen == [25]


def test_run_catch_up_cycle_routes_cve_to_single_timestamp_run(monkeypatch) -> None:
    calls: list[tuple[int, str, bool, bool]] = []

    class FakeScraper:
        def __init__(
            self,
            settings,
            *,
            provider=None,
            stop_on_first_known=None,
            stop_on_unchanged_content=False,
            cve_delta_catch_up=False,
        ) -> None:
            calls.append(
                (
                    settings.limit,
                    settings.mongo_conflict,
                    stop_on_unchanged_content,
                    cve_delta_catch_up,
                )
            )

        async def run(self):
            return {
                "stop_reason": "timestamp_boundary",
                "result_count": 500,
                "vulnerabilities": [],
                "mongo_sync": {"inserted": 500},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(
        "vuln_scraper.catch_up.providers_for_catch_up",
        lambda settings: [CVEProvider()],
    )
    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    run_catch_up_cycle(
        default_scrape_settings(limit=2),
        max_runs_per_provider=1,
        batch_size=1,
    )

    assert calls == [(2, "overwrite", False, True)]


def test_providers_for_catch_up_returns_all_when_unconfigured(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.defaults]
        retries = 2
        """,
        encoding="utf-8",
    )

    settings = default_scrape_settings().normalized()
    settings = replace(settings, scrapers_config_file=config_file)

    keys = [provider.key for provider in providers_for_catch_up(settings)]

    assert keys == [provider.key for provider in all_providers()]


def test_providers_for_catch_up_respects_configured_list(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["zeroday", "hkcert", "zeroday"]
        """,
        encoding="utf-8",
    )

    settings = default_scrape_settings().normalized()
    settings = replace(settings, scrapers_config_file=config_file)

    keys = [provider.key for provider in providers_for_catch_up(settings)]

    assert keys == ["zeroday", "hkcert"]


def test_providers_for_catch_up_rejects_unknown_provider(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["hkcert", "not-a-provider"]
        """,
        encoding="utf-8",
    )

    settings = default_scrape_settings().normalized()
    settings = replace(settings, scrapers_config_file=config_file)

    with pytest.raises(ValueError, match="unknown catch-up provider"):
        providers_for_catch_up(settings)


def test_run_catch_up_cycle_uses_configured_providers(monkeypatch, tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
        [scrapers.catch_up]
        providers = ["hkcert"]
        """,
        encoding="utf-8",
    )
    calls: list[str] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None, stop_on_first_known=None, stop_on_unchanged_content=False, updated_since=None) -> None:
            self.provider = provider or HKCERTProvider()

        async def run(self):
            calls.append(self.provider.key)
            return {
                "stop_reason": "timestamp_boundary",
                "result_count": 0,
                "vulnerabilities": [],
                "mongo_sync": {"inserted": 0},
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("vuln_scraper.catch_up.ScraperRunner", FakeScraper)
    monkeypatch.setattr("vuln_scraper.catch_up.asyncio.run", fake_asyncio_run)

    settings = default_scrape_settings().normalized()
    settings = replace(settings, scrapers_config_file=config_file)
    run_catch_up_cycle(settings)

    assert calls == ["hkcert"]
