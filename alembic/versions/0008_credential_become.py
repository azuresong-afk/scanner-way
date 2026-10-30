"""Повышение прав учётной записи и рекомендация в находке (R1a).

* host_credentials.become — как повышать права на хосте для аудита
  конфигураций: ``sudo`` (по умолчанию; пароль учётки подаётся sudo через
  stdin, для ключа — NOPASSWD) или ``none``. Существующие учётки получают
  ``sudo``: auth_inventory поле не использует, его поведение не меняется.
* findings.remediation — рекомендация по устранению, которую дал сам модуль
  (fixtext правила OpenSCAP, решение Lynis). Отчёт по прогону строится из БД,
  и без этой колонки рекомендация бенчмарка терялась бы между прогоном и
  выгрузкой. Старые находки остаются с NULL.

Revision ID: 0008
Revises: 0007
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE host_credentials ADD COLUMN become TEXT NOT NULL DEFAULT 'sudo'")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT host_credentials_become_check "
               "CHECK (become IN ('sudo', 'none'))")
    op.execute("ALTER TABLE findings ADD COLUMN remediation TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS remediation")
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_become_check")
    op.execute("ALTER TABLE host_credentials DROP COLUMN IF EXISTS become")
