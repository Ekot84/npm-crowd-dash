"""Sends the automatic abuse report over SMTP. Deliberately stdlib-only
(smtplib) rather than pulling in an async SMTP dependency — this fires at
most a handful of times a day (once per newly-qualifying repeat offender),
so a sync call run in a worker thread is simpler than adding a new
dependency for something this infrequent."""

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from .config import settings

log = logging.getLogger("mailer")


class SmtpNotConfigured(Exception):
    """Raised when AUTO_ABUSE_REPORT is on but required SMTP settings are missing."""


def smtp_configured() -> bool:
    try:
        _require_smtp_settings()
        return True
    except SmtpNotConfigured:
        return False


def _require_smtp_settings() -> None:
    missing = [
        name
        for name, value in (
            ("SMTP_HOST", settings.smtp_host),
            ("SMTP_USER", settings.smtp_user),
            ("SMTP_PASSWORD", settings.smtp_password),
            ("SMTP_FROM", settings.smtp_from),
        )
        if not value
    ]
    if missing:
        raise SmtpNotConfigured(f"AUTO_ABUSE_REPORT is enabled but missing: {', '.join(missing)}")


def _send_sync(recipient: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = recipient
    msg.set_content(body)

    context = ssl.create_default_context()
    if settings.smtp_port == 465:
        # Implicit TLS from the start of the connection.
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context, timeout=30) as server:
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
    else:
        # Plain connection upgraded via STARTTLS (587 and most other ports).
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as server:
            server.starttls(context=context)
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)


async def send_abuse_report_email(recipient: str, subject: str, body: str) -> None:
    """Raises SmtpNotConfigured or whatever smtplib/ssl raises on failure —
    callers (poller._check_auto_abuse_reports) are responsible for catching,
    logging, and recording the failure so a single bad send doesn't crash
    the poll loop."""
    _require_smtp_settings()
    await asyncio.to_thread(_send_sync, recipient, subject, body)
