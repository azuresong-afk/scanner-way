"""Автономный режим узлов-сканеров: задания, переносимые на носителе.

* offline_jobs — одно задание на прогон, назначенный на автономный узел
  (scan_nodes.mode = 'offline', миграция 0028). Хранит файл задания (он уже
  подписан ключом центра и зашифрован на ключ узла) для повторного скачивания,
  его SHA-256 и отпечаток ключа узла, на который задание выпущено, — по ним
  при загрузке результата отклоняются чужие, повторные и подменённые файлы.
  status: exported (ожидает результат) | imported | cancelled | expired.

Только новая таблица; downgrade её удаляет.

Revision ID: 0029
Revises: 0028
"""
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE offline_jobs (
            id               TEXT PRIMARY KEY,
            run_id           BIGINT NOT NULL UNIQUE
                             REFERENCES scan_runs(id) ON DELETE CASCADE,
            node_id          BIGINT REFERENCES scan_nodes(id) ON DELETE SET NULL,
            node_fingerprint TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'exported'
                             CHECK (status IN ('exported', 'imported', 'cancelled',
                                               'expired')),
            job_sha256       TEXT NOT NULL,
            job_file         TEXT,
            exported_by      TEXT NOT NULL,
            exported_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at       TIMESTAMPTZ NOT NULL,
            imported_by      TEXT,
            imported_at      TIMESTAMPTZ,
            result_sha256    TEXT,
            result_summary   JSONB
        )""")
    op.execute("CREATE INDEX idx_offline_jobs_node ON offline_jobs(node_id, status)")
    op.execute("CREATE INDEX idx_offline_jobs_pending ON offline_jobs(expires_at) "
               "WHERE status = 'exported'")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS offline_jobs")
