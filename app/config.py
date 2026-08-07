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


settings = Settings()
