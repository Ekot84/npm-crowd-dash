"""Sends abuse-report email over SMTP. Deliberately stdlib-only (smtplib)
rather than pulling in an async SMTP dependency — this fires at most a
handful of times a day (once per newly-qualifying repeat offender, plus the
occasional manual test send from the Settings page), so a sync call run in
a worker thread is simpler than adding a new dependency for something this
infrequent.

Takes an explicit SmtpConfig rather than reading app.config.settings
directly, so the same send path serves two different config sources: the
real auto-report poller (config merged from runtime_settings, i.e. DB
overrides falling back to env vars) and the Settings page's "send test
email" button (config taken straight from the form as currently typed,
which may not be saved yet)."""

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

log = logging.getLogger("mailer")


@dataclass
class SmtpConfig:
    host: str | None
    port: int
    user: str | None
    password: str | None
    from_addr: str | None


class SmtpNotConfigured(Exception):
    """Raised when a send is attempted but the config is missing required fields."""


def is_configured(config: SmtpConfig) -> bool:
    try:
        _require(config)
        return True
    except SmtpNotConfigured:
        return False


def _require(config: SmtpConfig) -> None:
    missing = [
        name
        for name, value in (
            ("host", config.host),
            ("user", config.user),
            ("password", config.password),
            ("from address", config.from_addr),
        )
        if not value
    ]
    if missing:
        raise SmtpNotConfigured(f"missing SMTP settings: {', '.join(missing)}")


def _send_sync(config: SmtpConfig, recipient: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.from_addr
    msg["To"] = recipient
    msg.set_content(body)

    context = ssl.create_default_context()
    if config.port == 465:
        # Implicit TLS from the start of the connection.
        with smtplib.SMTP_SSL(config.host, config.port, context=context, timeout=30) as server:
            server.login(config.user, config.password)
            server.send_message(msg)
    else:
        # Plain connection upgraded via STARTTLS (587 and most other ports).
        with smtplib.SMTP(config.host, config.port, timeout=30) as server:
            server.starttls(context=context)
            server.login(config.user, config.password)
            server.send_message(msg)


async def send_email(config: SmtpConfig, recipient: str, subject: str, body: str) -> None:
    """Raises SmtpNotConfigured or whatever smtplib/ssl raises on failure.
    Callers are responsible for catching, logging/reporting, and (for the
    auto-report poller specifically) recording the failure so a single bad
    send doesn't crash the poll loop."""
    _require(config)
    await asyncio.to_thread(_send_sync, config, recipient, subject, body)
