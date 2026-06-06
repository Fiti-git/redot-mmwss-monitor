from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(..., description="postgresql://user:pass@host:port/db")
    mmwss_master_key: str = Field(..., min_length=64, max_length=64, description="32-byte hex for pgcrypto")
    cloudflare_api_token: str | None = Field(default=None, description="Bootstrap CF token; ingested on first run")
    cloudflare_token_label: str = Field(default="primary", description="Label for the bootstrap token row")

    uptime_probe_timeout_s: int = 10
    cf_user_agent: str = "mmwss-collector/0.1"

    # Slack incoming webhook URL (empty disables Slack alerts).
    slack_webhook_url: str = ""

    # Public base URL of MMWSS UI — used to build "View in MMWSS" buttons in alerts.
    mmwss_public_url: str = "https://coldcalling.redotglobal.agency"


def load() -> Settings:
    return Settings()
