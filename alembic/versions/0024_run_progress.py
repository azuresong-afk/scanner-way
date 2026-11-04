"""Прогресс идущего прогона для плашки в шапке интерфейса.

* scan_runs.progress — снимок хода прогона, пока он исполняется:
  {"stage": модуль, "stage_index": n, "stages": всего этапов,
  "hosts_done": хостов готово на этапе, "hosts_total": хостов в прогоне,
  "percent": общий процент, "updated_at": ISO-время}.
  NULL — прогон ещё в очереди или выполнен до этой миграции. Пишет
  исполнитель прогона (не чаще раза в пару секунд), на итог прогона не влияет.

Revision ID: 0024
Revises: 0023
"""
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_runs ADD COLUMN progress JSONB")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_runs DROP COLUMN progress")
