"""Автообновление справочников по расписанию (БДУ, NVD, шаблоны Nuclei).

* feed_sync — по строке на источник: расписание (как у scan_schedules), итог
  последнего обновления и момент следующего;
* running_since — метка «обновление идёт», чтобы не запускать второе параллельно.

Revision ID: 0011
Revises: 0010
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE feed_sync (
            source          TEXT PRIMARY KEY,
            kind            TEXT NOT NULL DEFAULT 'daily'
                            CHECK (kind IN ('daily', 'weekly', 'monthly')),
            time_of_day     TEXT NOT NULL DEFAULT '03:00',
            weekdays        JSONB NOT NULL DEFAULT '[]'::jsonb,
            month_day       INTEGER CHECK (month_day BETWEEN 1 AND 31),
            timezone        TEXT NOT NULL DEFAULT 'UTC',
            enabled         BOOLEAN NOT NULL DEFAULT FALSE,
            next_run_at     TIMESTAMPTZ,
            last_run_at     TIMESTAMPTZ,
            last_success_at TIMESTAMPTZ,
            last_result     TEXT,
            last_count      BIGINT,
            message         TEXT,
            fingerprint     TEXT,
            running_since   TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX idx_feed_sync_due ON feed_sync(next_run_at) WHERE enabled")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_feed_sync_due")
    op.execute("DROP TABLE IF EXISTS feed_sync")
