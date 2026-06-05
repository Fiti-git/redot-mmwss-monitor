from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(..., description="postgresql://user:pass@host:port/db")
    mmwss_master_key: str = Field(..., min_length=64, max_length=64)

    # Signed-cookie session secret (any random string >= 32 chars).
    session_secret: str = Field(..., min_length=32)

    # 8 hours
    session_max_age_seconds: int = 8 * 60 * 60

    base_path: str = "/mmwss"
    cookie_secure: bool = True
    cookie_samesite: str = "lax"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
