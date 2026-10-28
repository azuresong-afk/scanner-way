"""Конфигурация приложения (читается из окружения / .env)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "scanner"
    postgres_user: str = "scanner"
    postgres_password: str = "change_me"

    nvd_api_key: str = ""
    bdu_fstec_feed_path: str = "/data/bdu_fstec.xml"

    # gentle | normal | aggressive
    default_rate_profile: str = "gentle"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
