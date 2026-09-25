import pytest

from vuln_scraper.cli import build_parser, main


def test_cli_without_subcommand_has_no_command() -> None:
    parser = build_parser()
    args = parser.parse_args([])

    assert args.command is None


def test_cli_parses_unify_subcommand_with_custom_sources() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "unify-mongo",
            "--dry-run",
            "--source-collection",
            "legacy_hkcert",
            "--source-collection",
            "legacy_cve",
        ]
    )

    assert args.command == "unify-mongo"
    assert args.dry_run is True
    assert args.source_collections == ["legacy_hkcert", "legacy_cve"]


def test_cli_rejects_removed_backfill_severity_subcommand() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["backfill-severity"])


def test_cli_parses_run_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["run", "cnvd", "--limit", "25"])

    assert args.command == "run"
    assert args.provider == "cnvd"
    assert args.limit == 25


def test_cli_rejects_removed_flags() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--limit", "5"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-sync"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-filter-tui"])
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "cnvd", "--browser-headed"])
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "cnvd", "--no-browser-fallback"])
    with pytest.raises(SystemExit):
        parser.parse_args(["catch-up", "--include-manual-verification"])


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

    main(["run", "cnvd", "--limit", "1"])

    assert captured["provider"].key == "cnvd"
    assert captured["settings"].limit == 1
    assert "cnvd: fetched 1 records" in capsys.readouterr().out


def test_cli_rejects_removed_review_subcommand() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["review"])


def test_cli_syncs_source_catalog_without_starting_a_scraper(monkeypatch, capsys) -> None:
    published: list[dict] = []
    monkeypatch.setattr(
        "vuln_scraper.source_catalog.sync_source_catalog_to_mongo",
        lambda settings: published.append({"providers": ["fortiguard", "cve"]})
        or published[-1],
    )

    main(["sync-source-catalog"])

    assert published == [{"providers": ["fortiguard", "cve"]}]
    assert capsys.readouterr().out.strip() == "source-catalog: providers=2"
