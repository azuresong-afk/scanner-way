"""Учётки СУБД для аудита баз данных (db_audit).

* host_credentials.protocol — к ``ssh`` и ``winrm`` добавлены способы входа в
  СУБД: ``postgresql`` (в т. ч. Postgres Pro), ``mysql`` (MySQL и MariaDB),
  ``mssql`` и ``oracle``. Существующие учётки не меняются.
* host_credentials.db_name — база для входа (PostgreSQL, MS SQL) или имя
  сервиса Oracle; для SSH/WinRM пусто.

Только аддитивные изменения: ограничение протокола пересоздаётся с расширенным
списком, новая колонка допускает NULL.

Revision ID: 0026
Revises: 0025
"""
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_protocol_check")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT "
               "host_credentials_protocol_check CHECK (protocol IN "
               "('ssh', 'winrm', 'postgresql', 'mysql', 'mssql', 'oracle'))")
    op.execute("ALTER TABLE host_credentials ADD COLUMN IF NOT EXISTS db_name TEXT")


def downgrade() -> None:
    op.execute("DELETE FROM host_credentials WHERE protocol NOT IN ('ssh', 'winrm')")
    op.execute("ALTER TABLE host_credentials DROP COLUMN IF EXISTS db_name")
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_protocol_check")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT "
               "host_credentials_protocol_check CHECK (protocol IN ('ssh', 'winrm'))")
