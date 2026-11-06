"""Настройки API (переменные окружения с префиксом SCANNER_API_)."""
from __future__ import annotations

from typing import Literal

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

    # Секрет ключей центра для автономных узлов (подпись заданий, расшифровка
    # результатов). Пусто — ключ учёток, иначе secret. Отдельный секрет нужен,
    # чтобы смена SCANNER_API_SECRET не требовала переустанавливать ключ центра
    # на автономные узлы. Смена этого секрета = новый ключ центра.
    offline_key: str = Field(default="", validation_alias=AliasChoices(
        "SCANNER_OFFLINE_KEY", "SCANNER_API_OFFLINE_KEY"))

    # Первый администратор: создаётся при старте, только если в БД нет ни одного
    # пользователя. После создания переменные стоит убрать из окружения.
    bootstrap_admin: str = ""
    bootstrap_password: str = ""

    # Защита входа от перебора: столько неудачных попыток подряд -> пауза.
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # ---- Вход через LDAP/AD (опционально; по умолчанию выключен) ----
    # Пустой ldap_url — вход только локальными учётками, как раньше. Несколько
    # контроллеров — через запятую (пробуются по очереди). Схема ldaps:// —
    # TLS сразу; ldap:// — открытый канал, тогда обязателен ldap_start_tls.
    ldap_url: str = ""
    ldap_start_tls: bool = False
    # Проверка сертификата контроллера (выключать только в стенде) и свой
    # корневой сертификат организации (PEM, путь внутри контейнера).
    ldap_tls_verify: bool = True
    ldap_ca_file: str = ""
    # Служебная учётная запись для поиска пользователя (только чтение каталога).
    # Пусто — анонимный поиск (в AD обычно запрещён).
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    # Где и как искать пользователя; {username} — введённый логин (экранируется).
    ldap_user_base: str = ""
    ldap_user_filter: str = ("(&(objectClass=user)(|(sAMAccountName={username})"
                             "(userPrincipalName={username})))")
    # Атрибут с логином, под которым пользователь заводится в «Сканере», и
    # атрибут с отображаемым именем.
    ldap_username_attr: str = "sAMAccountName"
    ldap_display_name_attr: str = "displayName"
    # Группы → роли: «DN группы=>роль,роль» через «;». Пользователь без
    # подходящей группы не входит. Пример:
    # CN=Scanner-Admins,OU=Groups,DC=corp,DC=local=>admin;
    # CN=Scanner-Operators,OU=Groups,DC=corp,DC=local=>operator,host_credentials
    ldap_group_roles: str = ""
    # Учитывать вложенные группы (только Active Directory: правило
    # LDAP_MATCHING_RULE_IN_CHAIN). Выключено — только прямое членство (memberOf).
    ldap_nested_groups: bool = False
    ldap_timeout_seconds: float = 5.0

    # ---- Двухфакторный вход (TOTP, RFC 6238; опционально) ----
    # off — 2FA нет (по умолчанию); optional — каждый может включить себе в
    # профиле; required — обязательна для всех (кто не настроил — настроит при
    # следующем входе), кроме перечисленных в mfa_exempt_users (сервисные
    # учётки интеграций, через запятую).
    # Неизвестное значение — ошибка при старте API (опечатка не выключит 2FA молча).
    mfa: Literal["off", "optional", "required"] = "off"
    mfa_exempt_users: str = ""
    # Имя в приложении-аутентификаторе (Яндекс Ключ, Google Authenticator, …).
    mfa_issuer: str = "Scanner"

    # Сколько прогонов исполняется параллельно в процессе API.
    run_workers: int = 2

    # Восстановление после сбоя: как часто процесс отмечает «жив» у своих
    # прогонов и проверяет осиротевшие (секунды; 0 — выключено), и через
    # сколько секунд без отметки прогон считается осиротевшим (его процесс
    # упал): running -> «Прерван», pending -> снова в очередь.
    run_heartbeat_seconds: float = 30.0
    run_stale_seconds: float = 180.0

    # Планировщик прогонов по расписанию: как часто проверять, не пора ли
    # (секунды; 0 — выключен). Часовой пояс расписаний по умолчанию — если
    # браузер оператора не прислал свой.
    scheduler_tick_seconds: float = 30.0
    timezone: str = "Europe/Moscow"

    # Планировщик обновления справочников (БДУ/NVD/Nuclei): период проверки,
    # секунды; 0 — выключен.
    feeds_tick_seconds: float = 60.0

    # Уведомления (R9): как часто просматривать очередь повторов, секунды (0 —
    # выключено), и внешний адрес интерфейса для ссылок на отчёт в сообщениях
    # (https://scanner.example.local; пусто — ссылок нет).
    notify_tick_seconds: float = 30.0
    public_url: str = ""

    # /health/ready сверяет версию схемы БД с последней миграцией Alembic
    # (выключается только в тестах на схеме без Alembic).
    ready_check_migrations: bool = True

    # Проверок доступности хоста (без прогона) на пользователя в минуту.
    reachability_per_minute: int = 10

    # Проверка входа по учётным записям из «Активов»: хостов на пользователя в
    # минуту (массовая проверка тратит лимит по числу хостов) и сколько хостов
    # проверяется одновременно.
    credential_check_hosts_per_minute: int = 120
    credential_check_workers: int = 4

    # Проверка сетевой доступности (вкладка «Доступность», nmap): запусков на
    # пользователя в минуту, одновременных заданий у пользователя, адресов в
    # одном задании и сколько заданий исполняется параллельно в процессе API.
    portscan_per_minute: int = 6
    portscan_max_active: int = 2
    portscan_max_targets: int = 1024
    portscan_workers: int = 2

    # Origin'ы веб-интерфейса через запятую (https://scanner.example.local).
    # Пусто — CORS выключен: штатно интерфейс отдаётся с того же origin, что и
    # API (nginx из web/Dockerfile проксирует /api), и CORS не нужен.
    cors_origins: str = ""

    @property
    def mfa_exempt(self) -> frozenset[str]:
        return frozenset(u.strip().lower() for u in self.mfa_exempt_users.split(",")
                         if u.strip())

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]
