"""Слой БД: engine/session (SQLAlchemy 2.0) и ORM-отображение схемы.

Схема-источник — `db/migrations/0001_initial.sql` (применяется Alembic-миграцией
0001). ORM-классы ниже повторяют её один в один. Типы PostgreSQL (ARRAY, INET,
CIDR, JSONB) объявлены с вариантом для SQLite, чтобы тесты не требовали живого
Postgres; в проде используется только Postgres.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# BIGSERIAL в Postgres; в SQLite автоинкремент работает только у INTEGER PRIMARY KEY.
PK = BigInteger().with_variant(Integer(), "sqlite")
TextArray = postgresql.ARRAY(Text).with_variant(JSON(), "sqlite")
Inet = postgresql.INET().with_variant(String(64), "sqlite")
Cidr = postgresql.CIDR().with_variant(String(64), "sqlite")
Jsonb = postgresql.JSONB().with_variant(JSON(), "sqlite")
TsTz = DateTime(timezone=True)


class Base(DeclarativeBase):
    pass


# ========== RBAC ==========
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    username: Mapped[str] = mapped_column(Text, unique=True)
    display_name: Mapped[str | None] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


# ========== Engagement + allowlist ==========
class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    client: Mapped[str | None] = mapped_column(Text)
    contract_ref: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


class AllowlistEntry(Base):
    __tablename__ = "targets_allowlist"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(Cidr)
    note: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


# ========== Учётные записи активов ==========
class HostCredentialRow(Base):
    """Учётка для аутентифицированной инвентаризации. Секреты — только в
    secret_enc (зашифрованы CredentialVault), наружу не отдаются."""
    __tablename__ = "host_credentials"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(Text)
    auth: Mapped[str] = mapped_column(Text)              # password | key
    username: Mapped[str] = mapped_column(Text)
    port: Mapped[int] = mapped_column(Integer, default=22)
    targets: Mapped[list[str]] = mapped_column(TextArray, default=list)
    secret_enc: Mapped[str] = mapped_column(Text)
    key_fingerprint: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())
    # Повышение прав для аудита конфигураций: sudo | none (миграция 0008).
    become: Mapped[str] = mapped_column(Text, default="sudo", server_default="sudo")


# ========== Наборы проверки учёток (аудит паролей) ==========
class CredAuditSetRow(Base):
    """Набор проверяемых пар логин/секрет, заданный оператором под договор.

    Секреты — только в entries_enc (зашифрованы CredentialVault), наружу не
    отдаются. Встроенных словарей нет: набор целиком вводит оператор."""
    __tablename__ = "cred_audit_sets"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(Text)
    # Сервисы, к которым применять набор; пусто — все поддерживаемые.
    services: Mapped[list[str]] = mapped_column(TextArray, default=list)
    secret_enc: Mapped[str] = mapped_column("entries_enc", Text)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


# ========== Расписания ==========
class ScanSchedule(Base):
    """Прогон по расписанию: параметры прогона + когда его ставить в очередь.

    Запускается от имени owner_id — пользователя, который последним сохранил
    расписание; его права перепроверяются при каждом срабатывании.
    """
    __tablename__ = "scan_schedules"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str | None] = mapped_column(Text)        # None — имя по опциям
    targets: Mapped[list[str]] = mapped_column(TextArray, default=list)
    modules: Mapped[list[str]] = mapped_column(TextArray)
    rate_profile: Mapped[str] = mapped_column(Text, default="gentle")
    credential_ids: Mapped[list[int]] = mapped_column(Jsonb, default=list)
    # Наборы проверки учёток (cred_audit_sets.id) для модуля cred_audit.
    cred_set_ids: Mapped[list[int]] = mapped_column(Jsonb, default=list)
    kind: Mapped[str] = mapped_column(Text)               # once|daily|weekly|monthly
    time_of_day: Mapped[str | None] = mapped_column(Text)  # ЧЧ:ММ в timezone
    weekdays: Mapped[list[int]] = mapped_column(Jsonb, default=list)
    month_day: Mapped[int | None] = mapped_column(Integer)
    run_at: Mapped[datetime | None] = mapped_column(TsTz)
    timezone: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(TsTz, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(TsTz)
    last_result: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


# ========== Прогоны ==========
class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    started_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    modules: Mapped[list[str]] = mapped_column(TextArray)
    rate_profile: Mapped[str] = mapped_column(Text, default="gentle")
    # Учётные записи активов, выбранные для прогона (host_credentials.id).
    credential_ids: Mapped[list[int]] = mapped_column(Jsonb, default=list)
    # Наборы проверки учёток (cred_audit_sets.id) для модуля cred_audit.
    cred_set_ids: Mapped[list[int]] = mapped_column(Jsonb, default=list)
    # Имя по выбранным опциям (scanner.core.naming) или заданное оператором;
    # у прогонов до миграции 0006 — NULL.
    name: Mapped[str | None] = mapped_column(Text)
    targets: Mapped[list[str]] = mapped_column(TextArray, default=list)
    schedule_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_schedules.id", ondelete="SET NULL"), index=True)
    status: Mapped[str] = mapped_column(Text, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(TsTz)
    finished_at: Mapped[datetime | None] = mapped_column(TsTz)
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


class HostResult(Base):
    __tablename__ = "host_results"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(Inet)
    state: Mapped[str | None] = mapped_column(Text)
    os_guess: Mapped[str | None] = mapped_column(Text)
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    # Семейство ОС (scanner.core.osfamily) и источник: nmap | banner | ssh.
    # У хостов до миграции 0007 — NULL, семейство выводится из os_guess.
    os_family: Mapped[str | None] = mapped_column(Text)
    os_source: Mapped[str | None] = mapped_column(Text)


class ServiceResult(Base):
    __tablename__ = "service_results"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("host_results.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(Text)
    service: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)


class HostPackageRow(Base):
    """Установленный пакет хоста (аутентифицированная инвентаризация)."""
    __tablename__ = "host_packages"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(Inet)
    manager: Mapped[str] = mapped_column(Text)            # dpkg | rpm | apk
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    arch: Mapped[str | None] = mapped_column(Text)


# ========== Находки ==========
class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"))
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(Text)
    finding_type: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Inet)
    port: Mapped[int | None] = mapped_column(Integer)
    vuln_id: Mapped[str | None] = mapped_column(Text)
    cve_ids: Mapped[list[str]] = mapped_column(TextArray, default=list)
    bdu_ids: Mapped[list[str]] = mapped_column(TextArray, default=list)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, default="info")
    cvss: Mapped[Decimal | None] = mapped_column(Numeric(4, 1))
    evidence: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="open")
    dedup_key: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())
    # Рекомендация модуля (fixtext правила бенчмарка и т. п.), миграция 0008.
    remediation: Mapped[str | None] = mapped_column(Text)


class FalsePositiveRow(Base):
    """Отметка «ложное срабатывание»: действует на находку с этим dedup_key
    во всех прогонах договора, пока её не снимут (тогда строка удаляется,
    история остаётся в журнале аудита)."""
    __tablename__ = "false_positives"
    __table_args__ = (UniqueConstraint("engagement_id", "dedup_key"),)
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    dedup_key: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Inet)
    port: Mapped[int | None] = mapped_column(Integer)
    vuln_id: Mapped[str | None] = mapped_column(Text)
    module: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    marked_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    marked_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


# ========== Аудит (append-only) ==========
class AuditLogRow(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    ts: Mapped[datetime] = mapped_column(TsTz, server_default=func.now(), index=True)
    subject: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    result: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(Jsonb)


# ========== Активы (R7) ==========
asset_tags = Table(
    "asset_tags", Base.metadata,
    Column("asset_id", PK, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag", Text, primary_key=True),
)

asset_group_members = Table(
    "asset_group_members", Base.metadata,
    Column("asset_id", PK, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", PK, ForeignKey("asset_groups.id", ondelete="CASCADE"),
           primary_key=True),
)


class AssetRow(Base):
    """Актив (хост) договора: владелец, критичность, заметки. Теги и группы — в
    asset_tags / asset_group_members."""
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("engagement_id", "address"),)
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(Inet)
    hostname: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(Text)
    criticality: Mapped[str] = mapped_column(Text, default="medium")
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


class AssetGroupRow(Base):
    __tablename__ = "asset_groups"
    __table_args__ = (UniqueConstraint("engagement_id", "name"),)
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TsTz, server_default=func.now())


def make_engine(url: str | None = None, **kwargs) -> Engine:
    """Engine по URL; по умолчанию — Postgres из настроек окружения."""
    if url is None:
        from scanner.core.config import settings
        url = settings.database_url
    return create_engine(url, future=True, pool_pre_ping=True, **kwargs)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Транзакция: commit при успехе, rollback при исключении."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
