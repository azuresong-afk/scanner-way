"""Начальная схема: применяет db/migrations/0001_initial.sql.

SQL-файл остаётся единым источником схемы (его же монтирует docker-compose в
initdb). Все операторы в нём идемпотентны (IF NOT EXISTS), поэтому миграция
безопасна и на базе, уже инициализированной из initdb.

Revision ID: 0001
Revises:
"""
from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SQL_FILE = Path(__file__).resolve().parents[2] / "db" / "migrations" / "0001_initial.sql"

TABLES = [
    "audit_log", "reference_bdu_entry", "reference_nvd_cve", "findings",
    "service_results", "host_results", "scan_runs", "targets_allowlist",
    "engagements", "role_permissions", "user_roles", "permissions", "roles", "users",
]


def _statements(sql: str) -> list[str]:
    """Операторы SQL-файла без комментариев `--` (в схеме нет строк с `;`/`--`)."""
    body = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    return [s.strip() for s in body.split(";") if s.strip()]


def upgrade() -> None:
    # exec_driver_sql, а не op.execute(text): в комментариях схемы есть «BDU:YYYY»,
    # который text() принял бы за bind-параметр.
    bind = op.get_bind()
    for stmt in _statements(SQL_FILE.read_text(encoding="utf-8")):
        bind.exec_driver_sql(stmt)


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
