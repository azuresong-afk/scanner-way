"""Распределённые сканеры: узлы в изолированных сегментах.

* scan_nodes — узлы-сканеры. mode: online — узел сам выходит на центр по HTTPS
  с токеном (хранится только SHA-256 токена и его первые символы для
  опознания), offline — задания и результаты переносятся файлами (автономный
  режим, миграция 0029). scope — сети узла, заданные администратором (CIDR и
  диапазоны): центр отдаёт узлу только цели из allowlist договора внутри этих
  сетей. allow_credentials — можно ли передавать узлу учётные записи
  договора. public_key — открытый ключ узла (автономный режим). hostname,
  version, info — что узел сообщил о себе при регистрации; last_seen_at —
  последний выход на связь.
* scan_runs.node_id, scan_schedules.node_id — где исполнять прогон: NULL —
  центральный сервер, иначе узел. Удаление узла не удаляет прогоны.

Только аддитивные изменения; downgrade удаляет колонки и таблицу.

Revision ID: 0028
Revises: 0027
"""
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_nodes (
            id                BIGSERIAL PRIMARY KEY,
            name              TEXT NOT NULL UNIQUE,
            description       TEXT,
            mode              TEXT NOT NULL DEFAULT 'online'
                              CHECK (mode IN ('online', 'offline')),
            scope             JSONB NOT NULL DEFAULT '[]'::jsonb,
            allow_credentials BOOLEAN NOT NULL DEFAULT true,
            enabled           BOOLEAN NOT NULL DEFAULT true,
            token_hash        TEXT UNIQUE,
            token_prefix      TEXT,
            public_key        TEXT,
            hostname          TEXT,
            version           TEXT,
            info              JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_by        BIGINT REFERENCES users(id) ON DELETE SET NULL,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            registered_at     TIMESTAMPTZ,
            last_seen_at      TIMESTAMPTZ
        )""")
    op.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS node_id BIGINT "
               "REFERENCES scan_nodes(id) ON DELETE SET NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_node_pending ON scan_runs(node_id) "
               "WHERE node_id IS NOT NULL AND status IN ('pending', 'running')")
    op.execute("ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS node_id BIGINT "
               "REFERENCES scan_nodes(id) ON DELETE SET NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_scan_runs_node_pending")
    op.execute("ALTER TABLE scan_schedules DROP COLUMN IF EXISTS node_id")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS node_id")
    op.execute("DROP TABLE IF EXISTS scan_nodes")
