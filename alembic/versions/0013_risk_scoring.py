"""Приоритизация риска (R6): справочники EPSS и CISA KEV.

* epss_score — вероятность эксплуатации CVE (EPSS) и перцентиль;
* kev        — CVE из каталога CISA KEV с датой добавления (срок устранения не храним).

Только новые таблицы; заполняются загрузчиками из feed_sync (источники epss, kev).

Revision ID: 0013
Revises: 0012
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE epss_score (
            cve         TEXT PRIMARY KEY,
            score       NUMERIC(7, 6) NOT NULL CHECK (score BETWEEN 0 AND 1),
            percentile  NUMERIC(7, 6),
            as_of       TEXT
        )
    """)
    op.execute("""
        CREATE TABLE kev (
            cve    TEXT PRIMARY KEY,
            added  TEXT
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS kev")
    op.execute("DROP TABLE IF EXISTS epss_score")
