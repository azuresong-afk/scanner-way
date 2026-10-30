"""Pydantic-схемы запросов и ответов API."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scanner.api.security import MIN_PASSWORD_LEN
from scanner.core.naming import run_title


class _Orm(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- auth / users ----
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=1024)
    display_name: str | None = Field(default=None, max_length=256)
    roles: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=256)
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LEN,
                                 max_length=1024)


class RolesIn(BaseModel):
    roles: list[str]


class UserOut(_Orm):
    id: int
    username: str
    display_name: str | None
    is_active: bool
    roles: list[str] = Field(default_factory=list)


class MeOut(UserOut):
    permissions: list[str]


# ---- engagements / allowlist ----
class EngagementIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    client: str | None = Field(default=None, max_length=256)
    contract_ref: str | None = Field(default=None, max_length=256)


class EngagementUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    client: str | None = Field(default=None, max_length=256)
    contract_ref: str | None = Field(default=None, max_length=256)


class EngagementOut(_Orm):
    id: int
    name: str
    client: str | None
    contract_ref: str | None
    created_by: int | None
    created_at: datetime | None


class AllowlistIn(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=512)


class AllowlistOut(_Orm):
    id: int
    cidr: str
    note: str | None
    added_by: int | None
    added_at: datetime | None

    @field_validator("cidr", mode="before")
    @classmethod
    def _cidr_str(cls, v: object) -> str:
        return str(v)      # psycopg отдаёт CIDR как ipaddress.IPv4Network


# ---- учётные записи активов ----
class CredentialIn(BaseModel):
    """Учётка для инвентаризации и аудита конфигураций по SSH. Секреты только на вход — API их не отдаёт."""
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    auth: str = Field(pattern="^(password|key)$")
    port: int = Field(default=22, ge=1, le=65535)
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    private_key: str | None = Field(default=None, min_length=1, max_length=16384)
    passphrase: str | None = Field(default=None, max_length=1024)
    # IP/подсети из allowlist договора; пусто — все цели прогона
    targets: list[str] = Field(default_factory=list, max_length=256)
    # Повышение прав для аудита конфигураций: sudo (пароль учётки / NOPASSWD) | none
    become: str = Field(default="sudo", pattern="^(sudo|none)$")

    def __repr__(self) -> str:      # секреты не должны попасть в логи
        return (f"CredentialIn(name={self.name!r}, username={self.username!r}, "
                f"auth={self.auth!r}, become={self.become!r})")

    __str__ = __repr__


class CredentialOut(_Orm):
    id: int
    engagement_id: int
    name: str
    username: str
    auth: str
    port: int
    targets: list[str]
    key_fingerprint: str | None
    created_by: int | None
    created_at: datetime | None
    become: str = "sudo"

    @field_validator("targets", mode="before")
    @classmethod
    def _targets_str(cls, v: object) -> list[str]:
        return [str(x) for x in (v or [])]


# ---- наборы проверки учёток (аудит паролей) ----
class CredEntryIn(BaseModel):
    """Одна проверяемая пара логин/секрет. Пустой секрет допустим (пустой пароль)."""
    username: str = Field(min_length=1, max_length=128)
    secret: str = Field(default="", max_length=16384)

    def __repr__(self) -> str:      # секрет не должен попасть в логи
        return f"CredEntryIn(username={self.username!r})"

    __str__ = __repr__


class CredSetIn(BaseModel):
    """Набор проверки учёток. Секреты только на вход — API их не отдаёт."""
    name: str = Field(min_length=1, max_length=128)
    # Сервисы, к которым применять набор; пусто — все поддерживаемые.
    services: list[str] = Field(default_factory=list, max_length=32)
    entries: list[CredEntryIn] = Field(min_length=1, max_length=200)

    def __repr__(self) -> str:
        return (f"CredSetIn(name={self.name!r}, services={self.services!r}, "
                f"entries={len(self.entries)})")

    __str__ = __repr__


class CredSetOut(_Orm):
    """Набор наружу: без секретов — имя, сервисы, число записей, маскированные логины."""
    id: int
    engagement_id: int
    name: str
    services: list[str] = Field(default_factory=list)
    entry_count: int
    masked_usernames: list[str] = Field(default_factory=list)
    created_by: int | None
    created_at: datetime | None


# ---- runs ----
class RunCreate(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=1024)
    modules: list[str] = Field(min_length=1)
    rate_profile: str = "gentle"
    # Движок поиска уязвимостей: nuclei (сеть, без учётки) | credentialed (пакеты
    # по учётной записи) | both. Если задан — заменяет vuln/auth_inventory в modules.
    vuln_engine: str | None = Field(default=None, pattern="^(nuclei|credentialed|both)$")
    credential_ids: list[int] = Field(default_factory=list, max_length=32)
    # Наборы проверки учёток для модуля cred_audit (аудит паролей по согласованию).
    cred_set_ids: list[int] = Field(default_factory=list, max_length=32)
    # Своё имя прогона; пусто — имя по выбранным опциям (модули и цели).
    name: str | None = Field(default=None, max_length=200)


class DeniedTargetOut(BaseModel):
    target: str
    reason: str
    count: int


class RunOut(_Orm):
    id: int
    engagement_id: int
    modules: list[str]
    rate_profile: str
    credential_ids: list[int] = Field(default_factory=list)
    cred_set_ids: list[int] = Field(default_factory=list)
    name: str | None = None
    targets: list[str] = Field(default_factory=list)
    schedule_id: int | None = None
    status: str
    started_by: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime | None

    @model_validator(mode="after")
    def _default_name(self) -> RunOut:
        # Прогоны до миграции 0006 без имени — подпись по модулям.
        if not self.name:
            self.name = run_title(self.modules, self.targets or ())
        return self


class RunCreated(RunOut):
    accepted_targets: int
    denied_targets: list[DeniedTargetOut]


# ---- расписания ----
class ScheduleIn(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    targets: list[str] = Field(min_length=1, max_length=1024)
    modules: list[str] = Field(min_length=1)
    rate_profile: str = "gentle"
    vuln_engine: str | None = Field(default=None, pattern="^(nuclei|credentialed|both)$")
    credential_ids: list[int] = Field(default_factory=list, max_length=32)
    cred_set_ids: list[int] = Field(default_factory=list, max_length=32)
    kind: str = Field(pattern="^(once|daily|weekly|monthly)$")
    time_of_day: str | None = None             # ЧЧ:ММ — для daily/weekly/monthly
    weekdays: list[int] = Field(default_factory=list, max_length=7)  # 0 — пн
    month_day: int | None = Field(default=None, ge=1, le=31)
    run_at: datetime | None = None             # для once
    timezone: str | None = None                # IANA; пусто — пояс сервера
    enabled: bool = True


class ScheduleToggle(BaseModel):
    enabled: bool


class ScheduleOut(_Orm):
    id: int
    engagement_id: int
    name: str | None
    title: str = ""
    targets: list[str]
    modules: list[str]
    rate_profile: str
    credential_ids: list[int] = Field(default_factory=list)
    cred_set_ids: list[int] = Field(default_factory=list)
    kind: str
    time_of_day: str | None
    weekdays: list[int] = Field(default_factory=list)
    month_day: int | None
    run_at: datetime | None
    timezone: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_result: str | None
    last_run_id: int | None = None
    owner_id: int | None
    created_at: datetime | None

    @field_validator("run_at", "next_run_at", "last_run_at", "created_at")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        # SQLite (тесты) отдаёт время без пояса; в БД оно всегда UTC
        return v.replace(tzinfo=UTC) if v is not None and v.tzinfo is None else v

    @model_validator(mode="after")
    def _title(self) -> ScheduleOut:
        self.title = self.name or run_title(self.modules, self.targets)
        return self


class FalsePositiveIn(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)

    @field_validator("reason")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None


class FalsePositiveMarkOut(BaseModel):
    reason: str | None
    marked_by: str | None
    marked_at: datetime | None


class FalsePositiveOut(FalsePositiveMarkOut):
    """Действующая отметка договора (без привязки к прогону)."""
    dedup_key: str
    host: str
    port: int | None
    vuln_id: str | None
    module: str
    title: str


class PriorityOut(BaseModel):
    """Приоритет исправления (R6): ранг в прогоне, балл, ярлык и факторы."""
    rank: int
    score: float
    label: str                 # critical | high | medium | low
    label_ru: str
    reasons: list[str]
    factors: dict


class FindingOut(BaseModel):
    id: int
    dedup_key: str
    module: str
    host: str
    port: int | None
    finding_type: str
    title: str
    severity: str
    vuln_id: str | None
    cve_ids: list[str]
    bdu_ids: list[str]
    cvss: float | None
    evidence: str | None
    status: str | None
    detected_at: datetime
    false_positive: FalsePositiveMarkOut | None = None
    # ПО, к которому относится находка (сервис на порту или пакет хоста);
    # None — не определено (аудит конфигурации, паролей, порт без баннера)
    software: str | None = None
    software_version: str | None = None
    software_source: str | None = None      # service | package
    # None — информационная находка или отмечена как ложное срабатывание
    priority: PriorityOut | None = None


class ServiceOut(BaseModel):
    host: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    cpe: str | None


class InventoryHostOut(BaseModel):
    host: str
    os_guess: str | None
    # Семейство ОС (astra, redos, ubuntu, debian, windows, linux…) и подпись к нему;
    # источник: nmap | banner | ssh; точность nmap в % (100 — прочитано на хосте).
    os_family: str | None = None
    os_family_label: str = "ОС не определена"
    os_source: str | None = None
    os_accuracy: int | None = None
    os_run_id: int | None = None
    run_ids: list[int]
    services_run_id: int | None
    services: list[ServiceOut]
    # Последний прогон, где хост инвентаризирован по учётной записи, и число пакетов
    packages_run_id: int | None = None
    package_count: int = 0


class PackageOut(BaseModel):
    host: str
    manager: str
    name: str
    version: str
    arch: str | None


# ---- audit ----
class AuditOut(_Orm):
    id: int
    ts: datetime
    subject: str
    action: str
    target: str | None
    result: str | None
    details: dict | None


# ---- проверка доступности ----
class ReachabilityIn(BaseModel):
    target: str = Field(min_length=1, max_length=64)
    ports: list[int] | None = Field(default=None, min_length=1, max_length=10)


class PortStateOut(BaseModel):
    port: int
    state: str                    # open | closed | filtered
    rtt_ms: float | None


class ReachabilityOut(BaseModel):
    target: str
    reachable: bool
    methods: list[str]            # icmp / tcp — чем подтверждена доступность
    icmp_available: bool          # есть ли ping в окружении API
    icmp_alive: bool
    icmp_rtt_ms: float | None
    ports: list[PortStateOut]
    elapsed_ms: float
    checked_at: datetime


# ---- активы (R7) ----
Criticality = Literal["low", "medium", "high", "critical"]


class AssetGroupRef(BaseModel):
    id: int
    name: str


class AssetIn(BaseModel):
    address: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=253)
    owner: str | None = Field(default=None, max_length=256)
    criticality: Criticality = "medium"
    notes: str | None = Field(default=None, max_length=4000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    group_ids: list[int] = Field(default_factory=list, max_length=100)


class AssetUpdate(BaseModel):
    """Частичная правка: меняются только переданные поля."""
    address: str | None = Field(default=None, min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=253)
    owner: str | None = Field(default=None, max_length=256)
    criticality: Criticality | None = None
    notes: str | None = Field(default=None, max_length=4000)
    tags: list[str] | None = Field(default=None, max_length=50)
    group_ids: list[int] | None = Field(default=None, max_length=100)


class AssetOut(BaseModel):
    id: int
    engagement_id: int
    address: str
    hostname: str | None
    owner: str | None
    criticality: Criticality
    notes: str | None
    tags: list[str]
    groups: list[AssetGroupRef]
    created_at: datetime | None
    # из последних прогонов (если хост в них встречался)
    os_guess: str | None = None
    os_family: str | None = None
    os_family_label: str | None = None
    last_run_id: int | None = None
    finding_counts: dict[str, int] = Field(default_factory=dict)
    findings_total: int = 0


class AssetBulkIn(BaseModel):
    asset_ids: list[int] = Field(min_length=1, max_length=2000)
    add_tags: list[str] = Field(default_factory=list, max_length=50)
    remove_tags: list[str] = Field(default_factory=list, max_length=50)
    add_group_ids: list[int] = Field(default_factory=list, max_length=100)
    remove_group_ids: list[int] = Field(default_factory=list, max_length=100)
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=256)


class AssetGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class AssetGroupOut(BaseModel):
    id: int
    engagement_id: int
    name: str
    asset_count: int
    created_at: datetime | None


class AssetTagOut(BaseModel):
    tag: str
    count: int
