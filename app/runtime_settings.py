"""Runtime-editable SMTP settings, backed by the `settings` key/value table
in SQLite (see db.py) instead of the env-only Settings in config.py.

Design: env vars (SMTP_HOST, ...) stay the *default* — anyone deploying via
docker-compose/.env only sees no change at all. The Settings page in the web
UI lets someone override any of these five fields at runtime; once a field
is saved there, it wins over the env value until changed again (or the row
is deleted, which this app never does automatically). Nothing here talks to
CrowdSec or changes ban behavior — this only supplies the SMTP config used
when someone sends a report from the Reports page (main.py's /reports/send
route). Sending only ever happens on that explicit action, never on a timer
or poll cycle — there is no automatic abuse-report sending in this app.
"""

from dataclasses import dataclass, field

from . import db, secrets_store
from .config import settings as env_settings

_KEYS = (
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
)


@dataclass
class SmtpSettings:
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_from: str | None
    # Which of the above came from a saved DB row rather than the env
    # default — the Settings page uses this to decide whether to show a
    # "leave blank to keep the saved password" placeholder.
    from_db: set[str] = field(default_factory=set)


def _decrypt_stored_password(stored: dict[str, str | None]) -> str | None:
    """None means "nothing saved in the DB for this key at all" (fall back to
    the env default, handled by the pick() in get_smtp_settings()).
    A saved-but-empty string (an explicitly cleared password) stays "" as-is
    — only a genuinely present, non-empty value goes through decryption."""
    raw = stored.get("smtp_password")
    if not raw:
        return raw
    if not secrets_store.is_key_configured():
        # No SETTINGS_SECRET_KEY -> nothing new can ever be saved this way
        # (see save_smtp_settings), so a value only ends up here from an old
        # pre-release install that had the now-removed auto-generated
        # key-file fallback. Not worth migrating (this feature never
        # shipped), and re-encrypting is impossible without a key anyway —
        # hand back the raw value rather than raising, so the rest of the
        # app keeps working; it just won't work as a real password until a
        # key is configured.
        return raw
    plaintext, was_encrypted = secrets_store.try_decrypt_password(raw)
    if not was_encrypted:
        # Plaintext password saved by a pre-encryption version of this app —
        # migrate it to encrypted storage right now, on this first read.
        db.set_settings({"smtp_password": secrets_store.encrypt_password(plaintext)})
    return plaintext


def get_smtp_settings() -> SmtpSettings:
    stored = db.get_settings(list(_KEYS))

    def pick(key: str, env_default):
        raw = stored.get(key)
        return raw if raw is not None else env_default

    smtp_password = (
        _decrypt_stored_password(stored) if "smtp_password" in stored else env_settings.smtp_password
    )

    return SmtpSettings(
        smtp_host=pick("smtp_host", env_settings.smtp_host),
        smtp_port=int(pick("smtp_port", str(env_settings.smtp_port))),
        smtp_user=pick("smtp_user", env_settings.smtp_user),
        smtp_password=smtp_password,
        smtp_from=pick("smtp_from", env_settings.smtp_from),
        from_db=set(stored.keys()),
    )


def save_smtp_settings(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str | None,
    smtp_from: str,
) -> bool:
    """smtp_password=None (or "") means "leave whatever's already saved (or
    the env default) unchanged" — the Settings form never redisplays the
    real saved password in the browser, so it can't submit it back on every
    resave; only a non-empty typed value overwrites it.

    A non-empty smtp_password can only be saved when SETTINGS_SECRET_KEY is
    configured (see secrets_store.py) — there is no weaker fallback to fall
    back to. If a password was submitted but no key is configured, it's
    silently dropped from this save (every other field still saves
    normally) and the return value is True so the caller (the /settings/save
    route) can tell the user their password specifically wasn't saved and
    why, rather than the save just quietly not doing what they asked."""
    values = {
        "smtp_host": smtp_host,
        "smtp_port": str(smtp_port),
        "smtp_user": smtp_user,
        "smtp_from": smtp_from,
    }
    password_rejected = False
    if smtp_password:
        if secrets_store.is_key_configured():
            values["smtp_password"] = secrets_store.encrypt_password(smtp_password)
        else:
            password_rejected = True
    db.set_settings(values)
    return password_rejected
