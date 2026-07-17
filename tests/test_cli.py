import pytest

from vuln_scraper.cli import build_parser, main


def test_cli_without_subcommand_has_no_command() -> None:
    parser = build_parser()
    args = parser.parse_args([])

    assert args.command is None


def test_cli_parses_review_subcommand() -> None:
    parser = build_parser()
    all_args = parser.parse_args(["review"])
    one_args = parser.parse_args(["review", "hikvision", "avd"])

    assert all_args.command == "review"
    assert all_args.providers == []
    assert one_args.providers == ["hikvision", "avd"]


def test_cli_parses_backfill_severity_subcommand() -> None:
    parser = build_parser()
    all_args = parser.parse_args(["backfill-severity"])
    one_args = parser.parse_args(["backfill-severity", "cnnvd", "--dry-run"])

    assert all_args.command == "backfill-severity"
    assert all_args.providers == []
    assert all_args.dry_run is False
    assert one_args.providers == ["cnnvd"]
    assert one_args.dry_run is True


def test_cli_parses_run_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "run",
            "cnvd",
            "--limit",
            "25",
            "--browser-headed",
            "--no-browser-fallback",
            "--manual-verification-timeout-seconds",
            "60",
        ]
    )

    assert args.command == "run"
    assert args.provider == "cnvd"
    assert args.limit == 25
    assert args.browser_headed
    assert args.no_browser_fallback
    assert args.manual_verification_timeout_seconds == 60


def test_cli_rejects_removed_flags() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--limit", "5"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-sync"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-filter-tui"])
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "cnvd", "--manual-verification-timeout-seconds", "0"])


def test_main_without_subcommand_exits() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2


def test_main_run_dispatches_single_provider(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeScraper:
        def __init__(self, settings, *, provider=None) -> None:
            captured["settings"] = settings
            captured["provider"] = provider

        async def run(self):
            return {
                "vulnerabilities": [{"details": {"cnvd": {"cnvd_id": "CNVD-2026-21550"}}}],
                "mongo_sync": {
                    "inserted": 1,
                    "overwritten": 0,
                    "skipped": 0,
                    "conflicts": 0,
                },
            }

    monkeypatch.setattr("vuln_scraper.runner.ScraperRunner", FakeScraper)

    main(["run", "cnvd", "--limit", "1", "--browser-headed", "--manual-verification-timeout-seconds", "7"])

    assert captured["provider"].key == "cnvd"
    assert captured["settings"].limit == 1
    assert captured["settings"].browser_headless is False
    assert captured["settings"].manual_verification_timeout_ms == 7000
    assert "cnvd: fetched 1 records" in capsys.readouterr().out


def test_main_review_refreshes_selected_providers(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeDatabase:
        def __getitem__(self, name: str) -> object:
            return object()

    class FakeClient:
        def __getitem__(self, name: str) -> FakeDatabase:
            return FakeDatabase()

        def close(self) -> None:
            captured["closed"] = True

    def fake_refresh_review_views(database, *, providers=None, mongo_config_file=None):
        captured["providers"] = providers
        captured["database"] = database
        from vuln_scraper.review_template import ReviewViewRefreshResult

        return [
            ReviewViewRefreshResult("hikvision", "hikvision", "hikvision_review", True),
            ReviewViewRefreshResult("avd", "avd", "avd_review", False, "source collection missing"),
        ]

    monkeypatch.setattr("vuln_scraper.mongo.create_mongo_client", lambda uri: FakeClient())
    monkeypatch.setattr("vuln_scraper.review_template.refresh_review_views", fake_refresh_review_views)

    main(["review", "hikvision", "avd"])

    assert captured["providers"] == ["hikvision", "avd"]
    assert captured["closed"] is True
    output = capsys.readouterr().out
    assert "hikvision: refreshed hikvision_review" in output
    assert "avd: skipped avd_review" in output
    assert "review: refreshed=1 skipped=1 failed=0 total=2" in output


def test_main_review_rejects_unknown_provider() -> None:
    with pytest.raises(SystemExit):
        main(["review", "not-a-provider"])


def test_main_run_can_disable_provider_browser_fallback(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeScraper:
        def __init__(self, settings, *, provider=None) -> None:
            captured["settings"] = settings
            captured["provider"] = provider

        async def run(self):
            return {
                "vulnerabilities": [],
                "mongo_sync": {
                    "inserted": 0,
                    "overwritten": 0,
                    "skipped": 0,
                    "conflicts": 0,
                },
            }

    monkeypatch.setattr("vuln_scraper.runner.ScraperRunner", FakeScraper)

    main(["run", "avd", "--limit", "1", "--no-browser-fallback"])

    assert captured["provider"].key == "avd"
    assert captured["provider"].browser_fallback is False
    assert "avd: fetched 0 records" in capsys.readouterr().out
