"""Наборы проверки учётных данных (аудит паролей на согласованных учётках).

* cred_audit_sets — набор проверяемых пар логин/секрет, заданный ОПЕРАТОРОМ под
  конкретный договор. Секреты только в зашифрованном виде (entries_enc,
  CredentialVault); наружу API их не отдаёт никогда. Встроенных словарей нет —
  набор целиком вводит оператор (ввод или файл), лимит записей на набор.
* scan_runs.cred_set_ids / scan_schedules.cred_set_ids — наборы, выбранные для
  прогона (расшифровываются только на время прогона, как учётки активов).

Wave-1 резервирует 0008 за R1a (config_audit на сохранённых учётках). Пока R1a
не смёржен, цепочка строится от текущей головы 0007; при слиянии после R1a
down_revision поднимается до "0008" (правило восходящего слияния волны 1).

Revision ID: 0009
Revises: 0007
"""
from alembic import op

revision = "0009"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE cred_audit_sets (
            id              BIGSERIAL PRIMARY KEY,
            engagement_id   BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            services        TEXT[] NOT NULL DEFAULT '{}',
            entries_enc     TEXT NOT NULL,
            entry_count     INTEGER NOT NULL DEFAULT 0,
            created_by      BIGINT REFERENCES users(id),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX idx_cred_audit_sets_engagement "
               "ON cred_audit_sets(engagement_id)")
    op.execute("ALTER TABLE scan_runs "
               "ADD COLUMN cred_set_ids JSONB NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE scan_schedules "
               "ADD COLUMN cred_set_ids JSONB NOT NULL DEFAULT '[]'::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_schedules DROP COLUMN IF EXISTS cred_set_ids")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS cred_set_ids")
    op.execute("DROP TABLE IF EXISTS cred_audit_sets")
