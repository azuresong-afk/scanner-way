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


# ---- runs ----
class RunCreate(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=1024)
    modules: list[str] = Field(min_length=1)
    rate_profile: str = "gentle"


class DeniedTargetOut(BaseModel):
    target: str
    reason: str
    count: int


class RunOut(_Orm):
    id: int
    engagement_id: int
    modules: list[str]
    rate_profile: str
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


# ---- audit ----
class AuditOut(_Orm):
    id: int
    ts: datetime
    subject: str
    action: str
    target: str | None
    result: str | None
    details: dict | None
