"""Профили соответствия ФСТЭК №117/21/239 и CIS (R5).

* compliance_profile — профили, выбранные для договора: уровень (класс ГИС,
  уровень защищённости ПДн, категория значимости КИИ, группа внедрения CIS),
  адаптация базового набора мер (исключённые / добавленные меры) и признак
  «включать в отчёт». Сами профили (меры и их проверки) — данные в коде
  (scanner/compliance/profiles/*.yaml), в БД только выбор договора.
* compliance_result — статус каждой меры профиля по хосту в конкретном прогоне
  (passed / failed / manual / na) и доказательства (какие проверки, какие
  находки). Меры «проверяется вручную» — строки с host = NULL.
* compliance_facts — какие проверки на хосте реально выполнялись в прогоне
  (правила OpenSCAP с итогом pass/fail, тесты Lynis, параметры Windows…):
  по ним результаты пересчитываются после обновления профилей. Без секретов.

Revision ID: 0015
Revises: 0014
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE compliance_profile (
            id             BIGSERIAL PRIMARY KEY,
            engagement_id  BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            profile        TEXT NOT NULL,
            level          TEXT,
            excluded       TEXT[] NOT NULL DEFAULT '{}',
            added          TEXT[] NOT NULL DEFAULT '{}',
            in_report      BOOLEAN NOT NULL DEFAULT TRUE,
            updated_by     BIGINT REFERENCES users(id),
            updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (engagement_id, profile)
        )
    """)
    op.execute("""
        CREATE TABLE compliance_result (
            id           BIGSERIAL PRIMARY KEY,
            scan_run_id  BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            profile      TEXT NOT NULL,
            host         INET,
            control      TEXT NOT NULL,
            status       TEXT NOT NULL
                         CHECK (status IN ('passed', 'failed', 'manual', 'na')),
            evidence     JSONB NOT NULL DEFAULT '{}'::jsonb
        )
    """)
    op.execute("CREATE INDEX idx_compliance_result_run ON compliance_result"
               "(scan_run_id, profile)")
    op.execute("""
        CREATE TABLE compliance_facts (
            scan_run_id  BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            host         INET NOT NULL,
            facts        JSONB NOT NULL DEFAULT '{}'::jsonb,
            PRIMARY KEY (scan_run_id, host)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS compliance_facts")
    op.execute("DROP TABLE IF EXISTS compliance_result")
    op.execute("DROP TABLE IF EXISTS compliance_profile")
