"""Сеансы входа: отзыв токена при выходе и продление входа.

* auth_sessions — по строке на вход. Токен доступа несёт sid сеанса; API
  принимает токен, только пока сеанс не отозван (выход, «завершить сеанс»,
  блокировка пользователя, смена пароля, сброс 2FA) и не истёк его предельный
  срок (expires_at, NULL — без предела). Продление токена (POST /auth/refresh)
  обновляет last_seen_at и выдаёт новый токен того же сеанса.

Только новая таблица; downgrade её удаляет. Токены, выпущенные до миграции
(без sid), больше не принимаются — после обновления нужно войти заново.

Revision ID: 0030
Revises: 0029
"""
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE auth_sessions (
            id             TEXT PRIMARY KEY,
            user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at     TIMESTAMPTZ,
            revoked_at     TIMESTAMPTZ,
            revoked_reason TEXT,
            method         TEXT,
            client         TEXT,
            user_agent     TEXT
        )
    """)
    op.execute("CREATE INDEX ix_auth_sessions_user_id ON auth_sessions (user_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS auth_sessions")
