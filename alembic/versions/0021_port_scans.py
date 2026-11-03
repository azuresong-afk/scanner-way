"""Проверка сетевой доступности — отдельная вкладка «Доступность».

* port_scans — задание проверки: цели (после allowlist), режим портов
  (top — 1000 популярных портов nmap, list — явный список/диапазоны),
  исключённые порты, без ping (-Pn), определение сервисов (-sV), профиль
  интенсивности, прогресс и итог по хостам (results). Живые хосты заносятся в
  «Активы» — счётчик assets_created.

Только новая таблица.

Revision ID: 0021
Revises: 0020
"""
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE port_scans (
            id                BIGSERIAL PRIMARY KEY,
            engagement_id     BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            status            TEXT NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued', 'running', 'done', 'failed',
                                                'stopped', 'interrupted')),
            requested_targets JSONB NOT NULL DEFAULT '[]',
            targets           JSONB NOT NULL DEFAULT '[]',
            port_mode         TEXT NOT NULL DEFAULT 'top'
                              CHECK (port_mode IN ('top', 'list')),
            ports             TEXT,
            exclude_ports     TEXT,
            no_ping           BOOLEAN NOT NULL DEFAULT false,
            service_detection BOOLEAN NOT NULL DEFAULT false,
            rate_profile      TEXT NOT NULL DEFAULT 'gentle',
            hosts_total       INTEGER NOT NULL DEFAULT 0,
            hosts_done        INTEGER NOT NULL DEFAULT 0,
            hosts_up          INTEGER NOT NULL DEFAULT 0,
            open_ports        INTEGER NOT NULL DEFAULT 0,
            assets_created    INTEGER NOT NULL DEFAULT 0,
            results           JSONB NOT NULL DEFAULT '[]',
            error             TEXT,
            actor             TEXT,
            started_by        BIGINT REFERENCES users(id),
            created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            started_at        TIMESTAMPTZ,
            finished_at       TIMESTAMPTZ
        )""")
    op.execute("CREATE INDEX idx_port_scans_engagement "
               "ON port_scans(engagement_id, created_at DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS port_scans")
