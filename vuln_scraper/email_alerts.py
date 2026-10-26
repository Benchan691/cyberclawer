"""Email alerts for scrape failures.

Reads SMTP relay settings from the webserver ``.env`` file (SMTP_HOST,
SMTP_PORT, SMTP_USERNAME, SMTP_FROM, SMTP_USE_TLS, SMTP_USE_SSL) and sends a
CSS-styled HTML report when a scrape run records failed URL fetches.  Alert
recipients and the dedupe window are configured in the ``[scrapers.email]``
table of ``scrapers.toml``; the same failure is only re-reported after the
window elapses so chronic failures do not email on every hourly run.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html import escape
from pathlib import Path
from typing import Any

from .config import load_scrapers_config
from .env_file import read_dotenv

logger = logging.getLogger(__name__)

DEFAULT_SMTP_ENV_FILE = Path("/home/cpcnet/webserver-rust-zimbra-candidate/.env")
DEFAULT_ALERT_RECIPIENTS: tuple[str, ...] = ("ben.chan@citictel-cpc.com",)
DEFAULT_REPEAT_HOURS = 24.0
DEFAULT_SMTP_TIMEOUT = 15.0
SMTP_FROM_NAME = "Vuln Bulletin Scraper"
MAX_FAILURES_IN_EMAIL = 50
MAX_ERROR_CHARS = 300
STATE_FILE_NAME = "email-alert-state.json"

_TRUTHY = {"1", "true", "yes", "on"}
_state_lock = threading.Lock()


@dataclass(frozen=True)
class EmailAlertConfig:
    enabled: bool = True
    to: tuple[str, ...] = DEFAULT_ALERT_RECIPIENTS
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    smtp_env_file: Path = DEFAULT_SMTP_ENV_FILE
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_from: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool | None = None
    smtp_use_ssl: bool | None = None
    repeat_hours: float = DEFAULT_REPEAT_HOURS
    subject_prefix: str = "[vuln-scraper]"
    timeout: float = DEFAULT_SMTP_TIMEOUT


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    from_addr: str
    username: str | None
    password: str | None
    use_tls: bool
    use_ssl: bool


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUTHY


def _as_recipients(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ValueError("email recipients must be a string or a list of strings")
    recipients = tuple(str(item).strip() for item in items if str(item).strip())
    return recipients


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def load_email_alert_config(scrapers_config_file: Path | str | None) -> EmailAlertConfig:
    """Build the alert config from the ``[scrapers.email]`` table (defaults when absent)."""
    config = load_scrapers_config(scrapers_config_file)
    table = config.get("email")
    table = table if isinstance(table, dict) else {}

    env_file = table.get("env_file")
    repeat_hours = table.get("repeat_hours")
    return EmailAlertConfig(
        enabled=_as_bool(table.get("enabled"), True),
        to=_as_recipients(table.get("to"), DEFAULT_ALERT_RECIPIENTS),
        cc=_as_recipients(table.get("cc"), ()),
        bcc=_as_recipients(table.get("bcc"), ()),
        smtp_env_file=Path(env_file) if env_file else DEFAULT_SMTP_ENV_FILE,
        smtp_host=table.get("host"),
        smtp_port=_as_int(table.get("port")),
        smtp_from=table.get("from"),
        smtp_username=table.get("username"),
        smtp_password=table.get("password"),
        smtp_use_tls=_as_bool(table.get("use_tls")) if "use_tls" in table else None,
        smtp_use_ssl=_as_bool(table.get("use_ssl")) if "use_ssl" in table else None,
        repeat_hours=float(repeat_hours) if repeat_hours is not None else DEFAULT_REPEAT_HOURS,
        subject_prefix=str(table.get("subject_prefix") or "[vuln-scraper]"),
        timeout=float(table.get("timeout") or DEFAULT_SMTP_TIMEOUT),
    )


def resolve_smtp_settings(config: EmailAlertConfig) -> SmtpSettings | None:
    """Resolve SMTP relay settings: TOML override > process env > webserver .env."""
    env = read_dotenv(Path(config.smtp_env_file)) if config.smtp_env_file else {}

    def env_or(name: str) -> str | None:
        value = os.getenv(name)
        if value:
            return value
        return env.get(name)

    host = config.smtp_host or env_or("SMTP_HOST")
    if not host:
        logger.warning(
            "email alert skipped: no SMTP host configured (set SMTP_HOST in %s)",
            config.smtp_env_file,
        )
        return None

    from_addr = config.smtp_from or env_or("SMTP_FROM") or env_or("SMTP_USERNAME")
    if not from_addr:
        logger.warning(
            "email alert skipped: no SMTP from address configured (set SMTP_FROM in %s)",
            config.smtp_env_file,
        )
        return None

    port = config.smtp_port or _as_int(env_or("SMTP_PORT")) or 25
    username = config.smtp_username or env_or("SMTP_USERNAME")
    password = config.smtp_password or env_or("SMTP_PASSWORD")
    use_tls = config.smtp_use_tls if config.smtp_use_tls is not None else _as_bool(env_or("SMTP_USE_TLS"))
    use_ssl = config.smtp_use_ssl if config.smtp_use_ssl is not None else _as_bool(env_or("SMTP_USE_SSL"))
    return SmtpSettings(
        host=host,
        port=port,
        from_addr=from_addr,
        username=username or None,
        password=password or None,
        use_tls=use_tls,
        use_ssl=use_ssl,
    )


def _failure_key(provider: str, failure: dict[str, Any]) -> str:
    return "|".join(
        (
            provider,
            str(failure.get("phase") or ""),
            str(failure.get("identity") or ""),
            str(failure.get("url") or ""),
            str(failure.get("error") or "")[:MAX_ERROR_CHARS],
        )
    )


class AlertState:
    """File-backed record of when each failure was last reported by email."""

    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / STATE_FILE_NAME
        self.sent: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            logger.warning("discarding unreadable email alert state file %s", self.path)
            return
        sent = data.get("sent") if isinstance(data, dict) else None
        if isinstance(sent, dict):
            self.sent = {str(key): str(value) for key, value in sent.items()}

    def _parse(self, timestamp: str) -> datetime | None:
        try:
            return datetime.fromisoformat(timestamp)
        except ValueError:
            return None

    def was_sent_within(self, key: str, *, now: datetime, window: timedelta) -> bool:
        last = self._parse(self.sent.get(key, ""))
        return last is not None and timedelta(0) <= now - last < window

    def mark(self, key: str, when: datetime) -> None:
        self.sent[key] = when.isoformat()

    def save(self, *, retain: timedelta) -> None:
        cutoff = datetime.now(UTC) - retain
        kept: dict[str, str] = {}
        for key, timestamp in self.sent.items():
            parsed = self._parse(timestamp)
            if parsed is not None and parsed >= cutoff:
                kept[key] = timestamp
        self.sent = kept
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _state_lock:
            tmp_path = self.path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps({"sent": self.sent}, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            tmp_path.replace(self.path)


def _truncate(text: Any) -> str:
    value = str(text or "")
    if len(value) > MAX_ERROR_CHARS:
        return value[:MAX_ERROR_CHARS] + "..."
    return value


def _render_failures_html(
    *,
    provider: str,
    failures: list[dict[str, Any]],
    fresh_keys: set[str],
    stop_reason: str | None,
    when_local: str,
) -> str:
    fresh_count = sum(1 for failure in failures if _failure_key(provider, failure) in fresh_keys)
    stop_badge = (
        f'<span style="display:inline-block;background:#7f1d1d;color:#fff;'
        f'padding:2px 8px;border-radius:4px;font-size:12px">stop_reason: {escape(stop_reason)}</span>'
        if stop_reason
        else ""
    )
    rows: list[str] = []
    shown = failures[:MAX_FAILURES_IN_EMAIL]
    for failure in shown:
        key = _failure_key(provider, failure)
        is_fresh = key in fresh_keys
        badge = (
            '<span style="background:#b91c1c;color:#fff;padding:1px 6px;'
            'border-radius:3px;font-size:11px">new</span>'
            if is_fresh
            else '<span style="background:#94a3b8;color:#fff;padding:1px 6px;'
            'border-radius:3px;font-size:11px">repeat</span>'
        )
        rows.append(
            f'<tr style="background:{escape("#ffffff" if len(rows) % 2 == 0 else "#f8fafc")}">'
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;'
            f'white-space:nowrap">{escape(str(failure.get("identity") or "-"))} {badge}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px">'
            f'{escape(str(failure.get("phase") or "-"))}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;'
            f'color:#b91c1c;word-break:break-word">{escape(_truncate(failure.get("error")))}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:12px;'
            f'color:#475569;word-break:break-all">{escape(str(failure.get("url") or "-"))}</td>'
            f'</tr>'
        )
    overflow = (
        f'<p style="margin:10px 0 0;font-size:12px;color:#64748b">'
        f'... and {len(failures) - len(shown)} more (see data/scraper-errors.log)</p>'
        if len(failures) > len(shown)
        else ""
    )
    return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="max-width:820px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
    <div style="background:#b91c1c;color:#ffffff;padding:20px 28px;">
      <h1 style="margin:0;font-size:20px;line-height:1.3;">&#9888; Vulnerability scraper failure alert</h1>
      <p style="margin:8px 0 0;font-size:13px;opacity:0.9;">
        provider <strong>{escape(provider)}</strong> &middot; {escape(when_local)}
      </p>
    </div>
    <div style="padding:20px 28px;">
      <p style="margin:0 0 14px;font-size:14px;color:#334155;">
        <strong>{len(failures)}</strong> URL fetch failure(s):
        <strong style="color:#b91c1c">{fresh_count}</strong> new,
        <strong>{len(failures) - fresh_count}</strong> repeat (already reported within the alert window).
        {stop_badge}
      </p>
      <table style="width:100%;border-collapse:collapse;">
        <thead>
          <tr style="background:#f1f5f9;text-align:left;">
            <th style="padding:8px 10px;font-size:12px;color:#475569;text-transform:uppercase;">Item</th>
            <th style="padding:8px 10px;font-size:12px;color:#475569;text-transform:uppercase;">Phase</th>
            <th style="padding:8px 10px;font-size:12px;color:#475569;text-transform:uppercase;">Error</th>
            <th style="padding:8px 10px;font-size:12px;color:#475569;text-transform:uppercase;">URL</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
      {overflow}
    </div>
    <div style="padding:14px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;">
      Automated alert from vuln-bulletin-scraper. Failures are also appended to
      <code>data/scraper-errors.log</code>. Repeats are re-sent only after the configured
      alert window has elapsed.
    </div>
  </div>
</body>
</html>"""


def _render_failures_text(
    *,
    provider: str,
    failures: list[dict[str, Any]],
    fresh_keys: set[str],
    stop_reason: str | None,
    when_local: str,
) -> str:
    lines = [
        f"Vulnerability scraper failure alert - provider {provider} - {when_local}",
        f"{len(failures)} URL fetch failure(s).",
    ]
    if stop_reason:
        lines.append(f"stop_reason: {stop_reason}")
    for failure in failures[:MAX_FAILURES_IN_EMAIL]:
        marker = "new" if _failure_key(provider, failure) in fresh_keys else "repeat"
        lines.append(
            f"- [{marker}] {failure.get('identity') or '-'} ({failure.get('phase') or '-'}): "
            f"{_truncate(failure.get('error'))} | {failure.get('url') or '-'}"
        )
    lines.append("(Full log: data/scraper-errors.log)")
    return "\n".join(lines)


def _open_smtp(settings: SmtpSettings):  # pragma: no cover - thin wrapper around smtplib
    if settings.use_ssl:
        return smtplib.SMTP_SSL(settings.host, settings.port, timeout=DEFAULT_SMTP_TIMEOUT)
    return smtplib.SMTP(settings.host, settings.port, timeout=DEFAULT_SMTP_TIMEOUT)


def _deliver(message: EmailMessage, settings: SmtpSettings, recipients: list[str]) -> None:
    with _open_smtp(settings) as server:
        if settings.use_tls and not settings.use_ssl:
            server.starttls(context=ssl.create_default_context())
        if settings.username and settings.password:
            server.login(settings.username, settings.password)
        server.send_message(message, from_addr=settings.from_addr, to_addrs=recipients)


def _send_message(
    config: EmailAlertConfig,
    settings: SmtpSettings,
    *,
    subject: str,
    html: str,
    text: str,
) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((SMTP_FROM_NAME, settings.from_addr))
    if config.to:
        message["To"] = ", ".join(config.to)
    if config.cc:
        message["Cc"] = ", ".join(config.cc)
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=settings.from_addr.partition("@")[2])
    message.set_content(text)
    message.add_alternative(html, subtype="html")

    recipients = [*config.to, *config.cc, *config.bcc]
    if not recipients:
        raise ValueError("email alert has no recipients")
    _deliver(message, settings, recipients)


def _local_timestamp() -> str:
    from .timestamps import LOCAL_TIMEZONE

    return datetime.now(LOCAL_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %Z")


def notify_scrape_failures(
    config: EmailAlertConfig,
    *,
    data_dir: Path,
    provider: str,
    failures: list[dict[str, Any]],
    stop_reason: str | None = None,
) -> bool:
    """Email the failure report for one run. Returns True when an email was sent.

    Only sends when at least one failure was not already reported within the
    configured repeat window, so chronic failures stay quiet between re-reports.
    """
    if not config.enabled:
        return False
    entries = [item for item in failures if isinstance(item, dict) and item]
    if not entries:
        return False
    if not (config.to or config.cc or config.bcc):
        logger.info("email alert skipped: no recipients configured")
        return False

    now = datetime.now(UTC)
    window = timedelta(hours=max(0.0, config.repeat_hours))
    state = AlertState(data_dir)
    fresh_keys = {
        _failure_key(provider, item)
        for item in entries
        if not state.was_sent_within(_failure_key(provider, item), now=now, window=window)
    }
    if not fresh_keys:
        logger.info(
            "email alert suppressed: all %d failure(s) for %s already reported within %.0fh",
            len(entries),
            provider,
            config.repeat_hours,
        )
        return False

    when_local = _local_timestamp()
    subject = (
        f"{config.subject_prefix} {provider}: {len(entries)} scrape failure(s)"
        + (f" (stopped: {stop_reason})" if stop_reason else "")
    )
    html = _render_failures_html(
        provider=provider,
        failures=entries,
        fresh_keys=fresh_keys,
        stop_reason=stop_reason,
        when_local=when_local,
    )
    text = _render_failures_text(
        provider=provider,
        failures=entries,
        fresh_keys=fresh_keys,
        stop_reason=stop_reason,
        when_local=when_local,
    )

    settings = resolve_smtp_settings(config)
    if settings is None:
        return False
    try:
        _send_message(config, settings, subject=subject, html=html, text=text)
    except Exception:
        logger.exception("failed to send scrape failure alert email for %s", provider)
        return False

    for item in entries:
        state.mark(_failure_key(provider, item), now)
    state.save(retain=timedelta(days=max(7.0, config.repeat_hours * 2)))
    logger.info("sent scrape failure alert email for %s (%d failure(s))", provider, len(entries))
    return True


def notify_scrape_exception(
    config: EmailAlertConfig,
    *,
    data_dir: Path,
    provider: str,
    error: BaseException,
) -> bool:
    """Email an alert when a scrape run crashed with an uncaught exception."""
    if not config.enabled:
        return False
    if not (config.to or config.cc or config.bcc):
        logger.info("email alert skipped: no recipients configured")
        return False

    now = datetime.now(UTC)
    window = timedelta(hours=max(0.0, config.repeat_hours))
    state = AlertState(data_dir)
    summary = f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]
    key = f"{provider}|EXCEPTION|{summary}"
    if state.was_sent_within(key, now=now, window=window):
        logger.info("email alert suppressed: %s crash already reported within %.0fh", provider, config.repeat_hours)
        return False

    when_local = _local_timestamp()
    subject = f"{config.subject_prefix} {provider}: scraper crashed ({type(error).__name__})"
    detail = escape(summary)
    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="max-width:820px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
    <div style="background:#b91c1c;color:#ffffff;padding:20px 28px;">
      <h1 style="margin:0;font-size:20px;">&#9888; Vulnerability scraper crashed</h1>
      <p style="margin:8px 0 0;font-size:13px;opacity:0.9;">
        provider <strong>{escape(provider)}</strong> &middot; {escape(when_local)}
      </p>
    </div>
    <div style="padding:20px 28px;">
      <p style="margin:0 0 10px;font-size:14px;color:#334155;">The scrape run aborted with an uncaught exception:</p>
      <pre style="margin:0;padding:14px;background:#fef2f2;border:1px solid #fecaca;border-radius:6px;
        font-family:Menlo,Consolas,monospace;font-size:13px;color:#7f1d1d;white-space:pre-wrap;word-break:break-word;">{detail}</pre>
    </div>
    <div style="padding:14px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;">
      Automated alert from vuln-bulletin-scraper. See scrape.log for the full traceback.
    </div>
  </div>
</body>
</html>"""
    text = f"Vulnerability scraper crashed - provider {provider} - {when_local}\n\n{summary}\n"

    settings = resolve_smtp_settings(config)
    if settings is None:
        return False
    try:
        _send_message(config, settings, subject=subject, html=html, text=text)
    except Exception:
        logger.exception("failed to send scrape exception alert email for %s", provider)
        return False

    state.mark(key, now)
    state.save(retain=timedelta(days=max(7.0, config.repeat_hours * 2)))
    logger.info("sent scrape exception alert email for %s", provider)
    return True
