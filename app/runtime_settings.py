"""Runtime-editable auto abuse-report settings, backed by the `settings`
key/value table in SQLite (see db.py) instead of the env-only Settings in
config.py.

Design: env vars (AUTO_ABUSE_REPORT, SMTP_HOST, ...) stay the *default* —
anyone deploying via docker-compose/.env only, the way the feature originally
shipped, sees no change at all. The Settings page in the web UI lets someone
override any of these seven fields at runtime; once a field is saved there,
it wins over the env value until changed again (or the row is deleted, which
this app never does automatically). Nothing here talks to CrowdSec or
changes ban behavior — this only affects whether/how the auto abuse-report
poller check (poller._check_auto_abuse_reports) sends email.
"""

from dataclasses import dataclass, field

from . import db, secrets_store
from .config import settings as env_settings

_KEYS = (
    "auto_abuse_report",
    "auto_abuse_threshold",
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
)


@dataclass
class AutoReportSettings:
    auto_abuse_report: bool
    auto_abuse_threshold: int
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_from: str | None
    # Which of the above came from a saved DB row rather than the env
    # default — the Settings page uses this to decide whether to show a
    # "leave blank to keep the saved password" placeholder.
    from_db: set[str] = field(default_factory=set)


def _to_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _decrypt_stored_password(stored: dict[str, str | None]) -> str | None:
    """None means "nothing saved in the DB for this key at all" (fall back to
    the env default, handled by the pick() in get_auto_report_settings()).
    A saved-but-empty string (an explicitly cleared password) stays "" as-is
    — only a genuinely present, non-empty value goes through decryption."""
    raw = stored.get("smtp_password")
    if not raw:
        return raw
    plaintext, was_encrypted = secrets_store.try_decrypt_password(raw)
    if not was_encrypted:
        # Plaintext password saved by a pre-encryption version of this app —
        # migrate it to encrypted storage right now, on this first read.
        db.set_settings({"smtp_password": secrets_store.encrypt_password(plaintext)})
    return plaintext


def get_auto_report_settings() -> AutoReportSettings:
    stored = db.get_settings(list(_KEYS))

    def pick(key: str, env_default):
        raw = stored.get(key)
        return raw if raw is not None else env_default

    smtp_password = (
        _decrypt_stored_password(stored) if "smtp_password" in stored else env_settings.smtp_password
    )

    return AutoReportSettings(
        auto_abuse_report=_to_bool(pick("auto_abuse_report", "true" if env_settings.auto_abuse_report else "false")),
        auto_abuse_threshold=int(pick("auto_abuse_threshold", str(env_settings.auto_abuse_threshold))),
        smtp_host=pick("smtp_host", env_settings.smtp_host),
        smtp_port=int(pick("smtp_port", str(env_settings.smtp_port))),
        smtp_user=pick("smtp_user", env_settings.smtp_user),
        smtp_password=smtp_password,
        smtp_from=pick("smtp_from", env_settings.smtp_from),
        from_db=set(stored.keys()),
    )


def save_auto_report_settings(
    *,
    auto_abuse_report: bool,
    auto_abuse_threshold: int,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str | None,
    smtp_from: str,
) -> None:
    """smtp_password=None (or "") means "leave whatever's already saved (or
    the env default) unchanged" — the Settings form never redisplays the
    real saved password in the browser, so it can't submit it back on every
    resave; only a non-empty typed value overwrites it. Whatever value does
    get saved is encrypted at rest (see secrets_store.py) — the caller
    always passes the plaintext as typed, never anything pre-encrypted."""
    values = {
        "auto_abuse_report": "true" if auto_abuse_report else "false",
        "auto_abuse_threshold": str(auto_abuse_threshold),
        "smtp_host": smtp_host,
        "smtp_port": str(smtp_port),
        "smtp_user": smtp_user,
        "smtp_from": smtp_from,
    }
    if smtp_password:
        values["smtp_password"] = secrets_store.encrypt_password(smtp_password)
    db.set_settings(values)
