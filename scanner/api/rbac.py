"""RBAC: роли, права и их связь с пользователями.

Таблицы `roles`, `permissions`, `user_roles`, `role_permissions` созданы
миграцией 0001 (`db/migrations/0001_initial.sql`); здесь — их ORM-отображение
и справочник ролей. Справочник засевается идемпотентно при старте API
(`seed_rbac`), так что состав прав роли задаётся кодом, а не ручными INSERT.

Роли (docs/architecture.md, раздел 9):
  * admin    — пользователи и роли, договоры, allowlist, журнал аудита;
  * operator — запуск/остановка прогонов, просмотр;
  * auditor  — только просмотр и экспорт отчётов, журнал аудита;
  * cred_audit — отдельное право на модуль аудита учётных данных. Не входит ни
    в одну базовую роль (включая admin) и выдаётся явно, вдобавок к operator;
  * host_credentials — отдельное право на учётные записи активов: заводить и
    удалять учётки договора и запускать с ними инвентаризацию по учётной
    записи (модуль auth_inventory). Тоже выдаётся только явно.
"""
from __future__ import annotations

import enum

from sqlalchemy import Column, ForeignKey, Table, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from scanner.core.db import PK, Base, User


class Perm(enum.StrEnum):
    MANAGE_USERS = "manage_users"
    MANAGE_ENGAGEMENTS = "manage_engagements"
    MANAGE_ALLOWLIST = "manage_allowlist"
    VIEW_ENGAGEMENTS = "view_engagements"
    RUN_SCAN = "run_scan"
    VIEW_REPORT = "view_report"
    VIEW_AUDIT = "view_audit"
    CRED_AUDIT = "cred_audit"
    HOST_CREDENTIALS = "host_credentials"


ROLE_PERMISSIONS: dict[str, frozenset[Perm]] = {
    "admin": frozenset({Perm.MANAGE_USERS, Perm.MANAGE_ENGAGEMENTS,
                        Perm.MANAGE_ALLOWLIST, Perm.VIEW_ENGAGEMENTS,
                        Perm.VIEW_REPORT, Perm.VIEW_AUDIT}),
    "operator": frozenset({Perm.VIEW_ENGAGEMENTS, Perm.RUN_SCAN, Perm.VIEW_REPORT}),
    "auditor": frozenset({Perm.VIEW_ENGAGEMENTS, Perm.VIEW_REPORT, Perm.VIEW_AUDIT}),
    "cred_audit": frozenset({Perm.CRED_AUDIT}),
    "host_credentials": frozenset({Perm.HOST_CREDENTIALS}),
}

# Модуль -> дополнительное право сверх run_scan.
MODULE_PERMISSIONS: dict[str, Perm] = {"cred_audit": Perm.CRED_AUDIT,
                                       "auth_inventory": Perm.HOST_CREDENTIALS}


user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", PK, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", PK, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions = Table(
    "role_permissions", Base.metadata,
    Column("role_id", PK, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", PK, ForeignKey("permissions.id", ondelete="CASCADE"),
           primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(PK, primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)


def seed_rbac(session: Session) -> None:
    """Приводит роли/права в БД к ROLE_PERMISSIONS (идемпотентно)."""
    perms = {p.name: p for p in session.scalars(select(Permission))}
    for p in Perm:
        if p.value not in perms:
            perms[p.value] = Permission(name=p.value)
            session.add(perms[p.value])
    roles = {r.name: r for r in session.scalars(select(Role))}
    for name, granted in ROLE_PERMISSIONS.items():
        role = roles.get(name) or Role(name=name)
        session.add(role)
        role.permissions = [perms[p.value] for p in sorted(granted)]
    session.flush()


def user_role_names(session: Session, user_id: int) -> list[str]:
    return list(session.scalars(
        select(Role.name).join(user_roles, user_roles.c.role_id == Role.id)
        .where(user_roles.c.user_id == user_id).order_by(Role.name)))


def user_permissions(session: Session, user_id: int) -> set[str]:
    rows = session.scalars(
        select(Permission.name)
        .join(role_permissions, role_permissions.c.permission_id == Permission.id)
        .join(user_roles, user_roles.c.role_id == role_permissions.c.role_id)
        .where(user_roles.c.user_id == user_id))
    return set(rows)


def set_user_roles(session: Session, user_id: int, names: list[str]) -> None:
    unknown = sorted(set(names) - set(ROLE_PERMISSIONS))
    if unknown:
        raise ValueError(f"unknown roles: {', '.join(unknown)}")
    ids = list(session.scalars(select(Role.id).where(Role.name.in_(names))))
    session.execute(user_roles.delete().where(user_roles.c.user_id == user_id))
    if ids:
        session.execute(user_roles.insert(),
                        [{"user_id": user_id, "role_id": rid} for rid in ids])
    session.flush()


def active_admin_ids(session: Session) -> set[int]:
    return set(session.scalars(
        select(User.id).join(user_roles, user_roles.c.user_id == User.id)
        .join(Role, Role.id == user_roles.c.role_id)
        .where(Role.name == "admin", User.is_active.is_(True))))
