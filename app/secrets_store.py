"""Encrypts the SMTP password at rest in SQLite, so a copy of the database
file on its own — a stray backup, a debug share, opening dashboard.db in a
random SQLite browser out of curiosity — doesn't hand over a plaintext mail
password. Uses Fernet (AES-128-CBC + HMAC, from the well-audited
`cryptography` package) rather than hand-rolled crypto.

This is deliberately scoped: it protects the *database file* on its own.
It is NOT protection against someone with full access to the running
container or its `/data` volume as a whole — see _load_or_create_key()
below for why, and choose SETTINGS_SECRET_KEY if that distinction matters
to your setup.
"""

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_KEY_FILE = Path(settings.db_path).parent / ".settings_key"
_fernet: Fernet | None = None


def _load_or_create_key() -> bytes:
    # Preferred: a key supplied via SETTINGS_SECRET_KEY, kept outside the
    # /data volume entirely (e.g. only in the container's env config) so it
    # doesn't travel with however /data gets backed up, copied, or shared.
    if settings.settings_secret_key:
        return settings.settings_secret_key.encode()

    # Default: auto-generated on first run, persisted alongside the
    # database. Zero-config, and still stops the database file from being
    # readable on its own — but since the key sits right next to what it
    # protects, anyone who copies the whole /data volume gets both. That's
    # a real, known limit of this default, not an oversight.
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes()

    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    try:
        os.chmod(_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — best-effort
    except OSError:
        pass
    return key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt_password(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def try_decrypt_password(stored: str) -> tuple[str, bool]:
    """Returns (plaintext, was_encrypted). was_encrypted=False means `stored`
    wasn't actually a Fernet token at all — it's a plaintext password saved
    by a version of this app from before encryption existed, returned
    as-is. Callers should treat that as a signal to re-save it through
    encrypt_password() so it's migrated on next read rather than staying
    plaintext forever."""
    try:
        return _get_fernet().decrypt(stored.encode()).decode(), True
    except InvalidToken:
        return stored, False
