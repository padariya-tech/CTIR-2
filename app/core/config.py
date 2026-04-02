from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    DATABASE_URL: str = (
        "mysql+aiomysql://ctir_user:ctir_pass@localhost:3306/ctir_db"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE: int = 3600

    # API
    API_SECRET_KEY: str = "dev-secret-key"
    API_TITLE: str = "CTIR – Central Threat Intelligence Repository"
    API_VERSION: str = "1.0.0"

    # ThreatFox
    THREATFOX_API_KEY: str = ""
    THREATFOX_BASE_URL: str = "https://threatfox-api.abuse.ch/api/v1/"
    THREATFOX_TIMEOUT_SECONDS: int = 30
    THREATFOX_MAX_RETRIES: int = 3
    THREATFOX_QUERY_DAYS: int = 1         # days of history to pull per run

    # Scheduler
    INGESTION_SCHEDULE_MINUTES: int = 60

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/ctir.log"


@lru_cache
def get_settings() -> Settings:
    return Settings()