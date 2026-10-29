"""Pydantic-схемы запросов и ответов API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scanner.api.security import MIN_PASSWORD_LEN


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
    """Учётка для инвентаризации по SSH. Секреты только на вход — API их не отдаёт."""
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    auth: str = Field(pattern="^(password|key)$")
    port: int = Field(default=22, ge=1, le=65535)
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    private_key: str | None = Field(default=None, min_length=1, max_length=16384)
    passphrase: str | None = Field(default=None, max_length=1024)
    # IP/подсети из allowlist договора; пусто — все цели прогона
    targets: list[str] = Field(default_factory=list, max_length=256)

    def __repr__(self) -> str:      # секреты не должны попасть в логи
        return f"CredentialIn(name={self.name!r}, username={self.username!r}, auth={self.auth!r})"

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

    @field_validator("targets", mode="before")
    @classmethod
    def _targets_str(cls, v: object) -> list[str]:
        return [str(x) for x in (v or [])]


# ---- runs ----
class RunCreate(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=1024)
    modules: list[str] = Field(min_length=1)
    rate_profile: str = "gentle"
    # Движок поиска уязвимостей: nuclei (сеть, без учётки) | credentialed (пакеты
    # по учётной записи) | both. Если задан — заменяет vuln/auth_inventory в modules.
    vuln_engine: str | None = Field(default=None, pattern="^(nuclei|credentialed|both)$")
    credential_ids: list[int] = Field(default_factory=list, max_length=32)


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
    status: str
    started_by: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime | None


class RunCreated(RunOut):
    accepted_targets: int
    denied_targets: list[DeniedTargetOut]


class FindingOut(BaseModel):
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
