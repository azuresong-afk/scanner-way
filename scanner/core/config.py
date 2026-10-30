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
    # Если задан, автообновление скачивает выгрузку БДУ отсюда (в закрытом
    # контуре оставьте пустым: обновляйте файл по bdu_fstec_feed_path вручную).
    bdu_fstec_feed_url: str = ""
    # Каталог шаблонов Nuclei; пусто — $HOME/nuclei-templates, как у самого Nuclei.
    nuclei_templates_dir: str = ""

    # Бюллетени дистрибутивов для учёта бэкпортов (R2): какие выпуски загружать
    # (семейство:выпуск через запятую; семейства — debian, ubuntu, rhel, alt,
    # astra, redos). Каталог файлов оператора (закрытый контур): файл
    # <семейство>-<выпуск>.xml[.bz2] или debian.json[.gz] там главнее адреса.
    advisory_releases: str = ("debian:bullseye,debian:bookworm,ubuntu:focal,"
                              "ubuntu:jammy,ubuntu:noble,rhel:8,rhel:9,alt:p10")
    advisory_dir: str = "/data/advisories"
    # Свой адрес выгрузки семейства ({release} подставляется); пусто — адрес
    # вендора по умолчанию (у Astra Linux и РЕД ОС его нет: файл или адрес оператора).
    advisory_url_debian: str = ""
    advisory_url_ubuntu: str = ""
    advisory_url_rhel: str = ""
    advisory_url_alt: str = ""
    advisory_url_astra: str = ""
    advisory_url_redos: str = ""

    # gentle | normal | aggressive
    default_rate_profile: str = "gentle"

    def advisory_urls(self) -> dict[str, str]:
        return {f: getattr(self, f"advisory_url_{f}") for f in
                ("debian", "ubuntu", "rhel", "alt", "astra", "redos")
                if getattr(self, f"advisory_url_{f}").strip()}

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
