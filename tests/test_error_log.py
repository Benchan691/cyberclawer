import json
import logging

from vuln_scraper.error_log import ScraperErrorLog, install_run_log_handler, log_uncaught_provider_error


def test_append_writes_json_line(tmp_path) -> None:
    log_path = tmp_path / "scraper-errors.log"
    error_log = ScraperErrorLog(log_path)

    error_log.append(
        provider="hkcert",
        phase="detail",
        identity="hkcert:abc",
        url="https://example.test/detail",
        error="timeout",
    )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["record_type"] == "failure"
    assert payload["provider"] == "hkcert"
    assert payload["phase"] == "detail"
    assert payload["error"] == "timeout"


def test_multiple_providers_share_one_file(tmp_path) -> None:
    log_path = tmp_path / "scraper-errors.log"
    error_log = ScraperErrorLog(log_path)
    error_log.append(
        provider="cve",
        phase="list",
        identity="LIST",
        url="https://example.test/list",
        error="HTTP 500",
    )
    error_log.append(
        provider="cnvd",
        phase="detail",
        identity="cnvd:2026-1",
        url="https://example.test/cnvd",
        error="gate blocked",
    )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    providers = {json.loads(line)["provider"] for line in lines}
    assert providers == {"cve", "cnvd"}


def test_disabled_when_path_is_none() -> None:
    error_log = ScraperErrorLog(None)
    error_log.append(
        provider="hkcert",
        phase="list",
        identity="LIST",
        url="",
        error="ignored",
    )


def test_log_uncaught_provider_error(tmp_path) -> None:
    log_uncaught_provider_error(
        data_dir=tmp_path,
        error_log_name="errors.log",
        provider="cisco",
        error=RuntimeError("boom"),
    )

    payload = json.loads((tmp_path / "errors.log").read_text(encoding="utf-8").strip())
    assert payload["provider"] == "cisco"
    assert payload["phase"] == "run"
    assert "RuntimeError" in payload["error"]


def test_install_run_log_handler_writes_info_messages(tmp_path) -> None:
    log_path = install_run_log_handler(tmp_path, "run.log")
    logger = logging.getLogger("vuln_scraper.test")
    logger.setLevel(logging.INFO)

    logger.info("hello %s", "world")

    payload = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert payload["record_type"] == "log"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "vuln_scraper.test"
    assert payload["message"] == "hello world"
