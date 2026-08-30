"""Encrypts the SMTP password at rest in SQLite, so a copy of the database
file on its own — a stray backup, a debug share, opening dashboard.db in a
random SQLite browser out of curiosity — doesn't hand over a plaintext mail
password. Uses Fernet (AES-128-CBC + HMAC, from the well-audited
`cryptography` package) rather than hand-rolled crypto.

Deliberately no auto-generated fallback key: an earlier version of this
module generated one on first run and stored it next to the database
(/data/.settings_key), but that key would then live in the same place as
whatever it protects — a copy of the whole /data volume gets both, which
defeats the point for anyone who cares about that distinction. The key now
comes ONLY from the SETTINGS_SECRET_KEY env var. No key configured means no
password can be encrypted, so the Settings page simply refuses to save one
(see runtime_settings.save_smtp_settings) rather than falling back
to something weaker. Everything else in the app is unaffected either way —
this only gates the one write path for the SMTP password.
"""

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_fernet: Fernet | None = None


class KeyNotConfigured(Exception):
    """Raised when an encrypt/decrypt is attempted but SETTINGS_SECRET_KEY isn't set."""


def is_key_configured() -> bool:
    return bool(settings.settings_secret_key)


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        if not settings.settings_secret_key:
            raise KeyNotConfigured("SETTINGS_SECRET_KEY is not set")
        _fernet = Fernet(settings.settings_secret_key.encode())
    return _fernet


def encrypt_password(plaintext: str) -> str:
    """Raises KeyNotConfigured if SETTINGS_SECRET_KEY isn't set — callers
    (runtime_settings.save_smtp_settings) are expected to check
    is_key_configured() first and skip saving instead of calling this."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def try_decrypt_password(stored: str) -> tuple[str, bool]:
    """Returns (plaintext, was_encrypted). was_encrypted=False means either
    `stored` wasn't a Fernet token at all (a plaintext password saved by a
    version of this app from before encryption existed) or no key is
    configured to check with — either way, the caller gets `stored` back
    unchanged rather than an exception. Never raises."""
    try:
        return _get_fernet().decrypt(stored.encode()).decode(), True
    except InvalidToken:
        return stored, False
    except KeyNotConfigured:
        return stored, False
