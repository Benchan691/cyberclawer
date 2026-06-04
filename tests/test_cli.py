import pytest

from vuln_scraper.cli import build_parser, main


def test_cli_without_subcommand_has_no_command() -> None:
    parser = build_parser()
    args = parser.parse_args([])

    assert args.command is None


def test_cli_parses_sync_hours() -> None:
    parser = build_parser()
    args = parser.parse_args(["sync", "3"])

    assert args.command == "sync"
    assert args.hours == 3.0
    assert not args.include_manual_verification


def test_cli_parses_sync_manual_verification_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(["sync", "3", "--include-manual-verification"])

    assert args.command == "sync"
    assert args.include_manual_verification


def test_cli_rejects_sync_hours_below_one() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["sync", "0.5"])


def test_cli_parses_tui_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["tui"])

    assert args.command == "tui"


def test_cli_parses_run_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "run",
            "cnvd",
            "--limit",
            "25",
            "--browser-headed",
            "--manual-verification-timeout-seconds",
            "60",
        ]
    )

    assert args.command == "run"
    assert args.provider == "cnvd"
    assert args.limit == 25
    assert args.browser_headed
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


def test_main_tui_dispatches(monkeypatch) -> None:
    called = {"tui": False}

    def fake_tui() -> None:
        called["tui"] = True

    monkeypatch.setattr("vuln_scraper.scrape_tui.run_scrape_tui", fake_tui)

    main(["tui"])

    assert called["tui"]


def test_main_sync_dispatches(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_periodic(hours: float, settings, *, include_manual_verification: bool = False) -> None:
        captured["hours"] = hours
        captured["settings"] = settings
        captured["include_manual_verification"] = include_manual_verification

    monkeypatch.setattr("vuln_scraper.sync.run_periodic_sync", fake_periodic)

    main(["sync", "3", "--include-manual-verification"])

    assert captured["hours"] == 3.0
    assert captured["settings"].mongo_enabled is True
    assert captured["settings"].browser_fallback is False
    assert captured["include_manual_verification"] is True


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
