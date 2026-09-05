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

    # Escalates a repeat local offender straight to a long ban once their
    # local-origin ban count reaches this threshold, by pushing a manual
    # decision to CrowdSec's LAPI (reusing the same machine/watcher login
    # already used to read alerts — see crowdsec_client.add_manual_ban).
    # Off by default: test it manually against the LAPI first with a short
    # duration before enabling on a live poller, since once on it acts on
    # real IPs automatically, every poll cycle.
    repeat_offender_escalation_enabled: bool = False
    repeat_offender_escalation_threshold: int = 8
    repeat_offender_escalation_duration: str = "8760h"

    # Used to actually send an abuse report from the Reports page (see
    # app/mailer.py) — nothing is ever emailed automatically. Set these (or
    # fill in the same fields on the Settings page) before the "Send report"
    # button on Reports will work; until then it just fails with a clear
    # "SMTP not configured" message, everything else in the dashboard is
    # unaffected.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None

    # Required to save an SMTP password via the Settings page in the web UI
    # (see app/secrets_store.py) — that's the only thing this key gates.
    # Must be a valid Fernet key (44 url-safe-base64 chars) — generate one
    # with:
    #   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Unset by default, and deliberately with no auto-generated fallback: if
    # it's not set, the Settings page still loads and everything else in the
    # dashboard works normally, but the SMTP password field is disabled and
    # a new password can't be saved until this is configured.
    settings_secret_key: str | None = None


settings = Settings()
