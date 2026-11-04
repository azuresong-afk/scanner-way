"""Лента событий прогона для «Сводки»: что сканер делает и что нашёл.

* run_events — события прогона по времени: начат/завершён, модуль начат/готов/
  с ошибкой, по хосту — новые и вернувшиеся уязвимости, закрытые, хост не
  проверен (покрытие). subject — кто («Прогон», модуль, хост), message — что,
  severity — уровень для цветной метки (у событий по находкам).

Для уже завершённых прогонов события восстанавливаются по сохранённым данным:
итог прогона и по хосту — новые и вернувшиеся уязвимости (без ложных
срабатываний). downgrade удаляет таблицу.

Revision ID: 0024
Revises: 0023
"""
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

_SEV_RANK = """CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                               WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"""


def upgrade() -> None:
    op.execute("""
        CREATE TABLE run_events (
            id          BIGSERIAL PRIMARY KEY,
            scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
            kind        TEXT NOT NULL,
            subject     TEXT NOT NULL,
            host        TEXT,
            severity    TEXT,
            message     TEXT NOT NULL,
            details     JSONB
        )""")
    op.execute("CREATE INDEX idx_run_events_run ON run_events(scan_run_id, id DESC)")

    # Прошлые прогоны: по хосту — новые и вернувшиеся уязвимости
    op.execute(f"""
        INSERT INTO run_events (scan_run_id, ts, kind, subject, host, severity, message)
        SELECT g.scan_run_id, g.ts,
               CASE g.status WHEN 'new' THEN 'host_new' ELSE 'host_regression' END,
               g.host, g.host,
               CASE g.top WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium'
                          ELSE 'low' END,
               CASE g.status WHEN 'new' THEN 'новых уязвимостей: ' || g.n
                             ELSE 'вернулись после исправления: ' || g.n END
        FROM (
            SELECT f.scan_run_id, host(f.host) AS host, f.status,
                   coalesce(r.finished_at, r.started_at, r.created_at) AS ts,
                   count(*) AS n, max({_SEV_RANK}) AS top
            FROM findings f
            JOIN scan_runs r ON r.id = f.scan_run_id
            WHERE f.status IN ('new', 'regression') AND f.severity <> 'info'
              AND NOT EXISTS (SELECT 1 FROM false_positives fp
                              WHERE fp.engagement_id = r.engagement_id
                                AND fp.dedup_key = f.dedup_key)
            GROUP BY f.scan_run_id, host(f.host), f.status,
                     coalesce(r.finished_at, r.started_at, r.created_at)
        ) g
    """)
    # …и итог прогона
    op.execute("""
        INSERT INTO run_events (scan_run_id, ts, kind, subject, message)
        SELECT r.id, coalesce(r.finished_at, r.started_at, r.created_at), 'run_finish',
               'Прогон',
               CASE r.status WHEN 'done' THEN 'завершён' WHEN 'partial' THEN 'завершён частично'
                             WHEN 'stopped' THEN 'остановлен' WHEN 'interrupted' THEN 'прерван'
                             ELSE 'завершился ошибкой' END
        FROM scan_runs r
        WHERE r.status IN ('done', 'partial', 'failed', 'stopped', 'interrupted')
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS run_events")
