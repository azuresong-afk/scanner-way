"""Учётные записи активов и пакеты хостов (аутентифицированная инвентаризация).

* host_credentials — учётки договора (логин + пароль или SSH-ключ); секреты
  только в зашифрованном виде (secret_enc);
* host_packages — установленные пакеты хостов по результатам прогона;
* scan_runs.credential_ids — учётки, выбранные для прогона.

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE host_credentials (
            id              BIGSERIAL PRIMARY KEY,
            engagement_id   BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            auth            TEXT NOT NULL CHECK (auth IN ('password', 'key')),
            username        TEXT NOT NULL,
            port            INTEGER NOT NULL DEFAULT 22,
            targets         TEXT[] NOT NULL DEFAULT '{}',
            secret_enc      TEXT NOT NULL,
            key_fingerprint TEXT,
            created_by      BIGINT REFERENCES users(id),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX idx_host_credentials_engagement "
               "ON host_credentials(engagement_id)")
    op.execute("""
        CREATE TABLE host_packages (
            id          BIGSERIAL PRIMARY KEY,
            scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            host        INET NOT NULL,
            manager     TEXT NOT NULL,
            name        TEXT NOT NULL,
            version     TEXT NOT NULL,
            arch        TEXT
        )
    """)
    op.execute("CREATE INDEX idx_host_packages_run ON host_packages(scan_run_id, host)")
    op.execute("ALTER TABLE scan_runs "
               "ADD COLUMN credential_ids JSONB NOT NULL DEFAULT '[]'::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS credential_ids")
    op.execute("DROP TABLE IF EXISTS host_packages")
    op.execute("DROP TABLE IF EXISTS host_credentials")
