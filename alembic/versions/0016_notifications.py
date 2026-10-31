"""Каналы уведомлений и журнал доставки (R9).

* integration_channel — канал: тип (smtp, telegram, syslog_cef, jira), открытая
  конфигурация (config), секреты (secret_enc — только в зашифрованном виде,
  CredentialVault), подписка на события (events) и фильтры маршрутизации
  (filters: порог опасности/приоритета, группы и владельцы активов, договоры);
* notification_log — по строке на доставку «событие × канал»: статус, число
  попыток, время следующей попытки (очередь повторов), сводка события (payload —
  без секретов), ключ дедупа и внешняя ссылка (например, ключ задачи Jira).

Revision ID: 0016
Revises: 0015
"""
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE integration_channel (
            id          BIGSERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL
                        CHECK (type IN ('smtp', 'telegram', 'syslog_cef', 'jira')),
            enabled     BOOLEAN NOT NULL DEFAULT TRUE,
            config      JSONB NOT NULL DEFAULT '{}'::jsonb,
            secret_enc  TEXT,
            events      JSONB NOT NULL DEFAULT '[]'::jsonb,
            filters     JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_by  BIGINT REFERENCES users(id),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE notification_log (
            id              BIGSERIAL PRIMARY KEY,
            channel_id      BIGINT NOT NULL REFERENCES integration_channel(id)
                            ON DELETE CASCADE,
            event           TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'retry', 'sent', 'failed')),
            attempts        INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TIMESTAMPTZ,
            last_error      TEXT,
            payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
            engagement_id   BIGINT REFERENCES engagements(id) ON DELETE SET NULL,
            scan_run_id     BIGINT REFERENCES scan_runs(id) ON DELETE SET NULL,
            dedup_key       TEXT,
            external_ref    TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            sent_at         TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX idx_notification_log_due ON notification_log(next_attempt_at) "
               "WHERE status IN ('pending', 'retry')")
    op.execute("CREATE INDEX idx_notification_log_channel ON notification_log"
               "(channel_id, created_at DESC)")
    op.execute("CREATE INDEX idx_notification_log_dedup ON notification_log"
               "(channel_id, dedup_key) WHERE dedup_key IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS notification_log")
    op.execute("DROP TABLE IF EXISTS integration_channel")
