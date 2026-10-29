"""Отметки «ложное срабатывание» на находках хостов.

Отметка привязана к договору и dedup_key находки (хост+порт+vuln_id+модуль),
поэтому действует и на следующие прогоны. Снятие отметки удаляет строку;
кто и когда ставил/снимал — в журнале аудита (append-only).

Revision ID: 0005
Revises: 0004
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE false_positives (
            id            BIGSERIAL PRIMARY KEY,
            engagement_id BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            dedup_key     TEXT NOT NULL,
            host          INET NOT NULL,
            port          INTEGER,
            vuln_id       TEXT,
            module        TEXT NOT NULL,
            title         TEXT NOT NULL,
            reason        TEXT,
            marked_by     BIGINT REFERENCES users(id),
            marked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (engagement_id, dedup_key)
        )
    """)
    op.execute("CREATE INDEX idx_false_positives_engagement "
               "ON false_positives(engagement_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS false_positives")
