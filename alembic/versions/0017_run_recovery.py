"""Восстановление прогонов после сбоя.

В scan_runs:
* error_message — понятная пользователю причина ошибки или прерывания;
* heartbeat_at  — отметка «исполнитель жив»; её обновляет процесс, который
  ведёт прогон (pending в его очереди или running). Прогон, чья отметка давно
  не обновлялась, считается осиротевшим (процесс упал / перезапущен);
* worker_id     — какой процесс ведёт прогон (host:pid:boot), чтобы после
  перезапуска контейнера сразу отличить свой «мёртвый» прогон от живого
  прогона из CLI;
* retry_of      — прогон, который повторяет этот (кнопка «Повторить»).

Новый статус interrupted («Прерван») — прогон шёл, когда процесс остановился.
Частичный индекс по активным статусам — для сторожа осиротевших прогонов.

Revision ID: 0017
Revises: 0016
"""
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_runs ADD COLUMN error_message TEXT")
    op.execute("ALTER TABLE scan_runs ADD COLUMN heartbeat_at TIMESTAMPTZ")
    op.execute("ALTER TABLE scan_runs ADD COLUMN worker_id TEXT")
    op.execute("ALTER TABLE scan_runs ADD COLUMN retry_of BIGINT "
               "REFERENCES scan_runs(id) ON DELETE SET NULL")
    op.execute("CREATE INDEX idx_runs_active ON scan_runs(status) "
               "WHERE status IN ('pending', 'running')")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_runs_active")
    # Прогоны «Прерван» в старой схеме — просто ошибка.
    op.execute("UPDATE scan_runs SET status = 'failed' WHERE status = 'interrupted'")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS retry_of")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS worker_id")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS heartbeat_at")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS error_message")
