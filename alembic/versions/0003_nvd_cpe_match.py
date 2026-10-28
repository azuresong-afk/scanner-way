"""Справочник сопоставления CPE (reference_nvd_cpe_match): применяет
db/migrations/0002_nvd_cpe_match.sql.

Таблицу ввёл модуль сопоставления (T2) как отдельный SQL-файл, но в цепочку
Alembic она не попала — `alembic upgrade head` создавал схему без неё, и
SQL-хранилище сопоставления (scanner/feeds/store.py) ломалось на БД,
инициализированной через Alembic. Эта миграция включает таблицу в цепочку,
оставляя SQL-файл единым источником (как 0001 для начальной схемы).

Revision ID: 0003
Revises: 0002
"""
from pathlib import Path

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

SQL_FILE = Path(__file__).resolve().parents[2] / "db" / "migrations" / "0002_nvd_cpe_match.sql"


def _statements(sql: str) -> list[str]:
    body = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    return [s.strip() for s in body.split(";") if s.strip()]


def upgrade() -> None:
    bind = op.get_bind()
    for stmt in _statements(SQL_FILE.read_text(encoding="utf-8")):
        bind.exec_driver_sql(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS reference_nvd_cpe_match CASCADE")
