from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_title: str = "Text Risk Analyzer API"
    app_description: str = "Backend сервиса для анализа подозрительных сообщений"
    app_version: str = "0.1.0"
    debug: bool = False

    api_prefix: str = "/api"
    api_v1_prefix: str = "/v1"

    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "text_risk_db"
    db_username: str = "postgres"
    db_password: str = "postgres"
    db_echo: bool = False

    # пока закладываем заранее, пригодится на следующем этапе
    jwt_secret_key: str = Field(default="CHANGE_ME_SECRET_KEY")
    jwt_alg: str = "HS256"
    jwt_ttl_seconds: int = 60 * 60 * 24

    # версия артефакта модели
    model_version: str = "spam_lr_char3-5_tfidf_v1"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.db_username}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()