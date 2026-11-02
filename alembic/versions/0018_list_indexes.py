"""Индексы для постраничных списков находок и прогонов.

Фильтры и сортировка находок выполняются в БД (GET /runs/{id}/findings с
limit/offset, сводка /findings/summary): составные индексы по прогону с
уровнем, модулем и хостом; список прогонов договора — новые сверху.

Revision ID: 0018
Revises: 0017
"""
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX idx_findings_run_severity ON findings(scan_run_id, severity)")
    op.execute("CREATE INDEX idx_findings_run_module ON findings(scan_run_id, module)")
    op.execute("CREATE INDEX idx_findings_run_host ON findings(scan_run_id, host, port)")
    op.execute("CREATE INDEX idx_runs_engagement_id_desc ON scan_runs(engagement_id, id DESC)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_runs_engagement_id_desc")
    op.execute("DROP INDEX IF EXISTS idx_findings_run_host")
    op.execute("DROP INDEX IF EXISTS idx_findings_run_module")
    op.execute("DROP INDEX IF EXISTS idx_findings_run_severity")
