"""Бюллетени дистрибутивов для учёта бэкпортов (R2).

* distro_advisory — (семейство, выпуск, пакет, CVE) → первая исправленная
  версия пакета дистрибутива | not_affected | open. Заполняется загрузчиком
  scanner.feeds.advisories (трекер Debian, OVAL Ubuntu/RHEL/ALT/Astra/РЕД ОС);
  auth_inventory сверяет с ним точную версию установленного пакета.

Revision ID: 0012
Revises: 0011
"""
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE distro_advisory (
            id            BIGSERIAL PRIMARY KEY,
            family        TEXT NOT NULL,
            release       TEXT NOT NULL,
            package       TEXT NOT NULL,
            cve           TEXT NOT NULL,
            status        TEXT NOT NULL
                          CHECK (status IN ('fixed', 'not_affected', 'open')),
            fixed_version TEXT,
            advisory_id   TEXT,
            loaded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX idx_distro_advisory_pkg "
               "ON distro_advisory(family, release, package)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_distro_advisory_pkg")
    op.execute("DROP TABLE IF EXISTS distro_advisory")
