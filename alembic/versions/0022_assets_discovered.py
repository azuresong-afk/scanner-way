"""«Активы» независимо от прогонов: каждый обнаруженный хост — актив.

* assets.source — откуда актив: manual (заведён вручную или правкой учёта),
  discovery (найден прогоном), netscan (найден сканированием портов на вкладке
  проверки доступности);
* assets.first_seen_at / last_seen_at — когда хост впервые и в последний раз
  был обнаружен (у заведённых вручную и ни разу не найденных — NULL).

Данные не теряются: всем хостам, уже встречавшимся в прогонах договора
(host_results, findings, host_packages), заводится актив source='discovery'
с критичностью по умолчанию; у существующих активов заполняются
first_seen_at / last_seen_at по тем же прогонам. Учётные поля существующих
активов не меняются. downgrade убирает только новые колонки — активы,
заведённые из прогонов, остаются (как после «Из найденных хостов»).

Revision ID: 0022
Revises: 0021
"""
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

_SEEN = """
    SELECT r.engagement_id AS engagement_id, s.host AS host,
           min(coalesce(r.finished_at, r.started_at, r.created_at)) AS first_seen,
           max(coalesce(r.finished_at, r.started_at, r.created_at)) AS last_seen
    FROM (SELECT scan_run_id, host FROM host_results
          UNION SELECT scan_run_id, host FROM findings
          UNION SELECT scan_run_id, host FROM host_packages) s
    JOIN scan_runs r ON r.id = s.scan_run_id
    GROUP BY r.engagement_id, s.host
"""


def upgrade() -> None:
    op.execute("ALTER TABLE assets ADD COLUMN source TEXT NOT NULL DEFAULT 'manual' "
               "CHECK (source IN ('manual', 'discovery', 'netscan'))")
    op.execute("ALTER TABLE assets ADD COLUMN first_seen_at TIMESTAMPTZ")
    op.execute("ALTER TABLE assets ADD COLUMN last_seen_at TIMESTAMPTZ")
    op.execute(f"""
        UPDATE assets a SET first_seen_at = seen.first_seen, last_seen_at = seen.last_seen
        FROM ({_SEEN}) seen
        WHERE seen.engagement_id = a.engagement_id AND host(seen.host) = host(a.address)
    """)
    op.execute(f"""
        INSERT INTO assets (engagement_id, address, source, first_seen_at, last_seen_at)
        SELECT seen.engagement_id, host(seen.host)::inet, 'discovery',
               seen.first_seen, seen.last_seen
        FROM ({_SEEN}) seen
        ON CONFLICT (engagement_id, address) DO NOTHING
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE assets DROP COLUMN IF EXISTS last_seen_at")
    op.execute("ALTER TABLE assets DROP COLUMN IF EXISTS first_seen_at")
    op.execute("ALTER TABLE assets DROP COLUMN IF EXISTS source")
