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


settings = Settings()
