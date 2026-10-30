"""Настройки API (переменные окружения с префиксом SCANNER_API_)."""
from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_API_", env_file=".env",
                                      extra="ignore")

    # Ключ подписи токенов доступа. Пустой — генерируется при старте процесса
    # (токены перестают действовать после перезапуска).
    secret: str = ""
    token_ttl_minutes: int = 60

    # Ключ шифрования учётных записей активов (не короче 16 символов). Пусто —
    # используется secret. Без обоих учётки нельзя завести и использовать.
    # Смена ключа делает сохранённые учётки нечитаемыми — их придётся завести заново.
    credentials_key: str = Field(default="", validation_alias=AliasChoices(
        "SCANNER_CREDENTIALS_KEY", "SCANNER_API_CREDENTIALS_KEY"))

    # Первый администратор: создаётся при старте, только если в БД нет ни одного
    # пользователя. После создания переменные стоит убрать из окружения.
    bootstrap_admin: str = ""
    bootstrap_password: str = ""

    # Защита входа от перебора: столько неудачных попыток подряд -> пауза.
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Сколько прогонов исполняется параллельно в процессе API.
    run_workers: int = 2

    # Планировщик прогонов по расписанию: как часто проверять, не пора ли
    # (секунды; 0 — выключен). Часовой пояс расписаний по умолчанию — если
    # браузер оператора не прислал свой.
    scheduler_tick_seconds: float = 30.0
    timezone: str = "Europe/Moscow"

    # Планировщик обновления справочников (БДУ/NVD/Nuclei): период проверки,
    # секунды; 0 — выключен.
    feeds_tick_seconds: float = 60.0

    # Проверок доступности хоста (без прогона) на пользователя в минуту.
    reachability_per_minute: int = 10

    # Origin'ы веб-интерфейса через запятую (https://scanner.example.local).
    # Пусто — CORS выключен: штатно интерфейс отдаётся с того же origin, что и
    # API (nginx из web/Dockerfile проксирует /api), и CORS не нужен.
    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]
