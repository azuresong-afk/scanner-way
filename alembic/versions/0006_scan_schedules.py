"""Прогоны по расписанию и имена прогонов.

* scan_schedules — расписания прогонов договора (параметры прогона + когда
  запускать; next_run_at в UTC);
* scan_runs.name — имя прогона по выбранным опциям или заданное оператором;
* scan_runs.targets — запрошенные цели (для имени и повторного запуска);
* scan_runs.schedule_id — расписание, по которому прогон поставлен.

Revision ID: 0006
Revises: 0005
"""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_schedules (
            id              BIGSERIAL PRIMARY KEY,
            engagement_id   BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            name            TEXT,
            targets         TEXT[] NOT NULL DEFAULT '{}',
            modules         TEXT[] NOT NULL,
            rate_profile    TEXT NOT NULL DEFAULT 'gentle',
            credential_ids  JSONB NOT NULL DEFAULT '[]'::jsonb,
            kind            TEXT NOT NULL
                            CHECK (kind IN ('once', 'daily', 'weekly', 'monthly')),
            time_of_day     TEXT,
            weekdays        JSONB NOT NULL DEFAULT '[]'::jsonb,
            month_day       INTEGER CHECK (month_day BETWEEN 1 AND 31),
            run_at          TIMESTAMPTZ,
            timezone        TEXT NOT NULL,
            enabled         BOOLEAN NOT NULL DEFAULT TRUE,
            next_run_at     TIMESTAMPTZ,
            last_run_at     TIMESTAMPTZ,
            last_result     TEXT,
            owner_id        BIGINT REFERENCES users(id),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX idx_scan_schedules_engagement "
               "ON scan_schedules(engagement_id)")
    op.execute("CREATE INDEX idx_scan_schedules_due "
               "ON scan_schedules(next_run_at) WHERE enabled")
    op.execute("ALTER TABLE scan_runs ADD COLUMN name TEXT")
    op.execute("ALTER TABLE scan_runs ADD COLUMN targets TEXT[] NOT NULL DEFAULT '{}'")
    op.execute("ALTER TABLE scan_runs ADD COLUMN schedule_id BIGINT "
               "REFERENCES scan_schedules(id) ON DELETE SET NULL")
    op.execute("CREATE INDEX idx_scan_runs_schedule ON scan_runs(schedule_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_scan_runs_schedule")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS schedule_id")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS targets")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS name")
    op.execute("DROP TABLE IF EXISTS scan_schedules")
