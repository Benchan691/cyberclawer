from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from vuln_scraper.email_alerts import (
    DEFAULT_ALERT_RECIPIENTS,
    EmailAlertConfig,
    AlertState,
    load_email_alert_config,
    notify_scrape_exception,
    notify_scrape_failures,
    resolve_smtp_settings,
)
from vuln_scraper.client import FetchError
from vuln_scraper.config import ScraperSettings
from vuln_scraper.runner import ScraperRunner

from tests.fake_avd_provider import FakeAvdProvider


SMTP_ENV_FILE = """
SMTP_HOST=172.16.32.19
SMTP_PORT=25
SMTP_USERNAME=newsletter@citictel-cpc.com
SMTP_FROM=newsletter@citictel-cpc.com
SMTP_USE_TLS=false
SMTP_USE_SSL=false
"""


class FakeSmtpServer:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.messages: list = []
        self.recipients: list[str] = []
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        return None

    def starttls(self, context=None) -> None:
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.logged_in = (username, password)

    def send_message(self, message, *, from_addr: str, to_addrs: list[str]) -> None:
        if self.fail:
            raise RuntimeError("smtp relay unreachable")
        self.messages.append(message)
        self.recipients.extend(to_addrs)


@pytest.fixture
def smtp_outbox(monkeypatch):
    server = FakeSmtpServer()
    monkeypatch.setattr("vuln_scraper.email_alerts._open_smtp", lambda settings: server)
    return server


@pytest.fixture
def alert_env_file(tmp_path) -> Path:
    path = tmp_path / "webserver.env"
    path.write_text(SMTP_ENV_FILE, encoding="utf-8")
    return path


def failure(**overrides) -> dict:
    entry = {
        "identity": "juniper:JSA80837",
        "type": "JSA",
        "code": "JSA80837",
        "phase": "detail",
        "url": "https://example.com/advisory/JSA80837",
        "error": "HTTP 503 for https://example.com/advisory/JSA80837",
        "updated_at": datetime.now(UTC).isoformat(),
    }
    entry.update(overrides)
    return entry


def test_load_email_alert_config_defaults_without_table(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text("[scrapers.defaults]\nretries = 3\n", encoding="utf-8")

    config = load_email_alert_config(config_file)

    assert config.enabled is True
    assert config.to == DEFAULT_ALERT_RECIPIENTS
    assert config.cc == ()
    assert config.bcc == ()
    assert config.repeat_hours == 24.0


def test_load_email_alert_config_parses_email_table(tmp_path) -> None:
    config_file = tmp_path / "scrapers.toml"
    config_file.write_text(
        """
[scrapers.email]
enabled = true
to = ["ben.chan@citictel-cpc.com"]
cc = ["ops@example.com", "soc@example.com"]
bcc = "audit@example.com"
repeat_hours = 6
env_file = "/tmp/webserver.env"
subject_prefix = "[scrape-alert]"
host = "relay.example.com"
port = 587
use_tls = true
""",
        encoding="utf-8",
    )

    config = load_email_alert_config(config_file)

    assert config.enabled is True
    assert config.to == ("ben.chan@citictel-cpc.com",)
    assert config.cc == ("ops@example.com", "soc@example.com")
    assert config.bcc == ("audit@example.com",)
    assert config.repeat_hours == 6.0
    assert config.smtp_env_file == Path("/tmp/webserver.env")
    assert config.smtp_host == "relay.example.com"
    assert config.smtp_port == 587
    assert config.smtp_use_tls is True


def test_resolve_smtp_settings_reads_webserver_env_file(alert_env_file) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file)

    settings = resolve_smtp_settings(config)

    assert settings is not None
    assert settings.host == "172.16.32.19"
    assert settings.port == 25
    assert settings.from_addr == "newsletter@citictel-cpc.com"
    assert settings.username == "newsletter@citictel-cpc.com"
    assert settings.use_tls is False
    assert settings.use_ssl is False


def test_resolve_smtp_settings_toml_overrides_env_file(alert_env_file, monkeypatch) -> None:
    monkeypatch.delenv("SMTP_HOST", raising=False)
    config = EmailAlertConfig(
        smtp_env_file=alert_env_file,
        smtp_host="relay2.example.com",
        smtp_port=2525,
        smtp_use_tls=True,
    )

    settings = resolve_smtp_settings(config)

    assert settings.host == "relay2.example.com"
    assert settings.port == 2525
    assert settings.from_addr == "newsletter@citictel-cpc.com"
    assert settings.use_tls is True


def test_resolve_smtp_settings_returns_none_without_host(tmp_path) -> None:
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("", encoding="utf-8")

    assert resolve_smtp_settings(EmailAlertConfig(smtp_env_file=empty_env)) is None


def test_notify_failures_sends_styled_html_and_updates_state(
    tmp_path, alert_env_file, smtp_outbox
) -> None:
    config = EmailAlertConfig(
        smtp_env_file=alert_env_file,
        to=("ben.chan@citictel-cpc.com",),
        cc=("cc@example.com",),
        bcc=("bcc@example.com",),
    )

    sent = notify_scrape_failures(
        config,
        data_dir=tmp_path,
        provider="juniper",
        failures=[failure()],
        stop_reason="error",
    )

    assert sent is True
    assert len(smtp_outbox.messages) == 1
    message = smtp_outbox.messages[0]
    assert message["To"] == "ben.chan@citictel-cpc.com"
    assert message["Cc"] == "cc@example.com"
    assert "bcc@example.com" in smtp_outbox.recipients
    assert "JSA80837" in message.get_body(preferencelist=("html",)).get_content()
    assert "&lt;script&gt;" not in message.get_body(preferencelist=("html",)).get_content()
    assert smtp_outbox.recipients == [
        "ben.chan@citictel-cpc.com",
        "cc@example.com",
        "bcc@example.com",
    ]
    state = json.loads((tmp_path / "email-alert-state.json").read_text(encoding="utf-8"))
    assert len(state["sent"]) == 1


def test_notify_failures_escapes_error_markup(tmp_path, alert_env_file, smtp_outbox) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file)

    notify_scrape_failures(
        config,
        data_dir=tmp_path,
        provider="avd",
        failures=[failure(error="<script>alert('xss')</script>", identity="avd:<b>1</b>")],
    )

    html = smtp_outbox.messages[0].get_body(preferencelist=("html",)).get_content()
    assert "&lt;script&gt;" in html
    assert "avd:&lt;b&gt;1&lt;/b&gt;" in html


def test_notify_failures_suppresses_repeat_within_window(
    tmp_path, alert_env_file, smtp_outbox
) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file)
    failures = [failure(), failure(identity="juniper:JSA112528", url="https://example.com/x")]

    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=failures) is True
    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=failures) is False
    assert len(smtp_outbox.messages) == 1


def test_notify_failures_resends_after_repeat_window(
    tmp_path, alert_env_file, smtp_outbox
) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file, repeat_hours=24)

    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[failure()]) is True

    state_path = tmp_path / "email-alert-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    stale = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    state["sent"] = {key: stale for key in state["sent"]}
    state_path.write_text(json.dumps(state), encoding="utf-8")

    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[failure()]) is True
    assert len(smtp_outbox.messages) == 2


def test_notify_failures_partial_new_failures_still_send(
    tmp_path, alert_env_file, smtp_outbox
) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file)
    known = failure()
    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[known]) is True

    fresh = failure(identity="juniper:JSA999999", url="https://example.com/new")
    assert (
        notify_scrape_failures(
            config,
            data_dir=tmp_path,
            provider="juniper",
            failures=[known, fresh],
        )
        is True
    )
    html = smtp_outbox.messages[1].get_body(preferencelist=("html",)).get_content()
    assert "repeat" in html and "new" in html
    assert smtp_outbox.messages[1]["Subject"].startswith("[vuln-scraper] juniper: 2 scrape failure(s)")


def test_notify_failures_does_not_mark_state_when_send_fails(
    tmp_path, alert_env_file, monkeypatch
) -> None:
    monkeypatch.setattr(
        "vuln_scraper.email_alerts._open_smtp",
        lambda settings: FakeSmtpServer(fail=True),
    )
    config = EmailAlertConfig(smtp_env_file=alert_env_file)

    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[failure()]) is False
    assert not (tmp_path / "email-alert-state.json").exists()


def test_notify_failures_skips_when_disabled_or_empty(
    tmp_path, alert_env_file, smtp_outbox
) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file, enabled=False)
    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[failure()]) is False

    config = EmailAlertConfig(smtp_env_file=alert_env_file, to=(), cc=(), bcc=())
    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[failure()]) is False

    config = EmailAlertConfig(smtp_env_file=alert_env_file)
    assert notify_scrape_failures(config, data_dir=tmp_path, provider="juniper", failures=[]) is False

    assert smtp_outbox.messages == []


def test_notify_exception_sends_and_dedupes(tmp_path, alert_env_file, smtp_outbox) -> None:
    config = EmailAlertConfig(smtp_env_file=alert_env_file)

    assert (
        notify_scrape_exception(config, data_dir=tmp_path, provider="cve", error=RuntimeError("mongo down"))
        is True
    )
    assert (
        notify_scrape_exception(config, data_dir=tmp_path, provider="cve", error=RuntimeError("mongo down"))
        is False
    )
    assert len(smtp_outbox.messages) == 1
    assert "scraper crashed (RuntimeError)" in smtp_outbox.messages[0]["Subject"]
    assert "mongo down" in smtp_outbox.messages[0].get_body(preferencelist=("html",)).get_content()


def test_alert_state_ignores_corrupt_file(tmp_path) -> None:
    path = tmp_path / "email-alert-state.json"
    path.write_text("not json", encoding="utf-8")

    state = AlertState(tmp_path)

    assert state.sent == {}


def test_runner_sends_failure_alert_for_failed_url_scrapes(
    tmp_path, monkeypatch
) -> None:
    captured: dict = {}

    def fake_notify(config, **kwargs):
        captured.update(kwargs)
        return True

    monkeypatch.setattr("vuln_scraper.runner.notify_scrape_failures", fake_notify)
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "out.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=2,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    class FailingClient:
        async def get_html(self, url: str):
            raise FetchError(f"HTTP 500 for {url}")

    runner = ScraperRunner(settings, provider=FakeAvdProvider())
    output = asyncio.run(runner._run_with_client(FailingClient()))

    assert any("avd:LIST" in item["identity"] for item in output["failed"])
    asyncio.run(runner._finalize_run_output(output))

    assert captured["provider"] == "fake_avd"
    assert any("avd:LIST" in item["identity"] for item in captured["failures"])


def test_runner_does_not_alert_when_no_failures(tmp_path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(
        "vuln_scraper.runner.notify_scrape_failures",
        lambda config, **kwargs: calls.append(kwargs) or True,
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "out.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    class NoFailureClient:
        async def get_html(self, url: str):
            from tests.test_runner import detail_html, list_page_html
            from vuln_scraper.client import FetchResult

            if url.endswith("/list") or "list" in urlparse(url).path:
                page = int(parse_qs(urlparse(url).query)["page"][0])
                return FetchResult(html=list_page_html(page), status_code=200, url=url)
            avd_id = parse_qs(urlparse(url).query)["id"][0]
            return FetchResult(html=detail_html(avd_id), status_code=200, url=url)

    runner = ScraperRunner(settings, provider=FakeAvdProvider())
    output = asyncio.run(runner._run_with_client(NoFailureClient()))
    asyncio.run(runner._finalize_run_output(output))

    assert calls == []
    assert output["failed"] == []
