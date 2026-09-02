"""Sends abuse-report email over SMTP. Deliberately stdlib-only (smtplib)
rather than pulling in an async SMTP dependency — every send here is a
deliberate, one-at-a-time action a person just took (clicking "Send report"
on the Reports page, or "Send test email" on Settings), never something
running on a timer, so a sync call run in a worker thread is simpler than
adding a new dependency for something this infrequent.

Takes an explicit SmtpConfig rather than reading app.config.settings
directly, so the same send path serves two different config sources: the
Reports page's "Send report" button (config merged from runtime_settings,
i.e. DB overrides falling back to env vars) and the Settings page's "send
test email" button (config taken straight from the form as currently typed,
which may not be saved yet)."""

import asyncio
import logging
import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

log = logging.getLogger("mailer")


def _connect_ipv4(host: str, port: int, timeout: float | None) -> socket.socket:
    """Connects using only IPv4 addresses, skipping any IPv6 candidates
    getaddrinfo returns for the host.

    Plain socket.create_connection() (what smtplib normally uses under the
    hood) tries every address family getaddrinfo hands back, IPv6 included.
    On some Docker network setups IPv6 looks reachable at the interface
    level but has no real upstream route, so a send intermittently fails
    with "OSError: [Errno 101] Network is unreachable" whenever the
    resolver happens to hand back the host's IPv6 address first — seen in
    practice against smtp.gmail.com, which publishes both an A and an AAAA
    record. Every mail server this app talks to is reachable over IPv4, so
    skipping IPv6 entirely removes that flakiness instead of chasing a
    routing fix on every machine this ends up deployed on."""
    last_exc: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
        host, port, socket.AF_INET, socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            sock.close()
            last_exc = exc
    raise last_exc or OSError(f"no IPv4 address found for {host}")


class _IPv4SMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return _connect_ipv4(host, port, timeout)


class _IPv4SMTP_SSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        sock = _connect_ipv4(host, port, timeout)
        return self.context.wrap_socket(sock, server_hostname=self._host)


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
        with _IPv4SMTP_SSL(config.host, config.port, context=context, timeout=30) as server:
            server.login(config.user, config.password)
            server.send_message(msg)
    else:
        # Plain connection upgraded via STARTTLS (587 and most other ports).
        with _IPv4SMTP(config.host, config.port, timeout=30) as server:
            server.starttls(context=context)
            server.login(config.user, config.password)
            server.send_message(msg)


async def send_email(config: SmtpConfig, recipient: str, subject: str, body: str) -> None:
    """Raises SmtpNotConfigured or whatever smtplib/ssl raises on failure.
    Callers are responsible for catching, logging/reporting, and (for the
    Reports page's send-report action specifically) recording the failure
    so a bad send doesn't lose track of the report — it just stays pending
    for another manual attempt."""
    _require(config)
    await asyncio.to_thread(_send_sync, config, recipient, subject, body)
