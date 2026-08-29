from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    crowdsec_lapi_url: str = "http://127.0.0.1:8080"
    crowdsec_bouncer_key: str
    crowdsec_machine_id: str
    crowdsec_machine_password: str
    poll_interval_seconds: int = 15
    db_path: str = "/data/dashboard.db"
    retention_days: int = 90
    repeat_offender_threshold: int = 3
    country_ban_threshold: int = 10

    # Opt-in: automatically email the network's abuse contact once an IP
    # crosses auto_abuse_threshold bans, instead of relying on someone
    # clicking "Prepare abuse report" in the UI. Off by default — this sends
    # real email on your behalf, so it should be a deliberate choice.
    auto_abuse_report: bool = False
    auto_abuse_threshold: int = 8
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None

    # Optional: encrypts the SMTP password when it's saved to SQLite via the
    # Settings page (see app/secrets_store.py). Must be a valid Fernet key
    # (44 url-safe-base64 chars) if set — generate one with:
    #   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Unset by default: a key is instead auto-generated on first run and
    # persisted next to the database (still encrypted at rest, just with a
    # key that isn't kept separately from it — see secrets_store.py).
    settings_secret_key: str | None = None


settings = Settings()
