"""Настройки API (переменные окружения с префиксом SCANNER_API_)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_API_", env_file=".env",
                                      extra="ignore")

    # Ключ подписи токенов доступа. Пустой — генерируется при старте процесса
    # (токены перестают действовать после перезапуска).
    secret: str = ""
    token_ttl_minutes: int = 60

    # Первый администратор: создаётся при старте, только если в БД нет ни одного
    # пользователя. После создания переменные стоит убрать из окружения.
    bootstrap_admin: str = ""
    bootstrap_password: str = ""

    # Защита входа от перебора: столько неудачных попыток подряд -> пауза.
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Сколько прогонов исполняется параллельно в процессе API.
    run_workers: int = 2
