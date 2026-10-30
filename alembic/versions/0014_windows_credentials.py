"""Учётки WinRM и справочник обновлений Microsoft (R3).

* host_credentials.protocol — способ входа: ``ssh`` (по умолчанию; все
  существующие учётки остаются SSH, поведение SSH-модулей не меняется) или
  ``winrm`` (Windows: HTTPS + NTLM, только пароль) для модуля win_inventory.
* reference_msrc_fix — исправления из бюллетеней MSRC (CVRF): какая KB
  закрывает CVE для какого продукта Windows, какую KB она замещает
  (supersedence) и с какой сборки ОС уязвимость закрыта (FixedBuild).
  Справочник, как NVD/БДУ, общий для всех договоров.

Revision ID: 0014
Revises: 0013
"""
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE host_credentials ADD COLUMN protocol TEXT NOT NULL "
               "DEFAULT 'ssh'")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT "
               "host_credentials_protocol_check CHECK (protocol IN ('ssh', 'winrm'))")
    op.execute("""
        CREATE TABLE reference_msrc_fix (
            id           BIGSERIAL PRIMARY KEY,
            release      TEXT NOT NULL,
            cve_id       TEXT NOT NULL,
            product_id   TEXT NOT NULL,
            product      TEXT NOT NULL,
            kb           TEXT NOT NULL,
            supersedes   TEXT[] NOT NULL DEFAULT '{}',
            fixed_build  TEXT,
            url          TEXT,
            severity     TEXT,
            cvss         NUMERIC(4, 1),
            title        TEXT,
            UNIQUE (release, cve_id, product_id, kb)
        )
    """)
    op.execute("CREATE INDEX idx_msrc_fix_product ON reference_msrc_fix(product)")
    op.execute("CREATE INDEX idx_msrc_fix_cve ON reference_msrc_fix(cve_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS reference_msrc_fix")
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_protocol_check")
    op.execute("ALTER TABLE host_credentials DROP COLUMN IF EXISTS protocol")
