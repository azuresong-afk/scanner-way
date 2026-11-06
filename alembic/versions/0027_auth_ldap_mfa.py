"""Вход через LDAP/AD и двухфакторный вход (TOTP) — оба опциональны.

* users.auth_source — откуда пользователь: local (логин и пароль в «Сканере»),
  ldap (учётная запись домена, роли из групп AD) или platform (зарезервировано
  под вход через «Платформу» по контракту v1, теневые пользователи по `sub`);
* users.external_dn — DN учётной записи в каталоге (для ldap, справочно);
* users.mfa_secret — секрет TOTP, зашифрованный ключом учётных записей
  (как секреты учёток активов); mfa_enabled — 2FA подтверждена и действует;
  mfa_last_step — последний принятый 30-секундный шаг (код нельзя
  использовать повторно); mfa_recovery — хэши одноразовых кодов
  восстановления (JSON-массив).

Существующие пользователи становятся auth_source='local' без 2FA: поведение
не меняется, пока администратор не включит LDAP или 2FA в окружении.
downgrade удаляет колонки (пользователи из каталога остаются как локальные
без пароля — войти не смогут).

Revision ID: 0027
Revises: 0026
"""
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local' "
               "CHECK (auth_source IN ('local', 'ldap', 'platform'))")
    op.execute("ALTER TABLE users ADD COLUMN external_dn TEXT")
    op.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    op.execute("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE users ADD COLUMN mfa_last_step BIGINT")
    op.execute("ALTER TABLE users ADD COLUMN mfa_recovery JSONB")


def downgrade() -> None:
    for col in ("mfa_recovery", "mfa_last_step", "mfa_enabled", "mfa_secret",
                "external_dn", "auth_source"):
        op.execute(f"ALTER TABLE users DROP COLUMN {col}")
