"""Семейство ОС хоста.

* host_results.os_family — astra, redos, alt, ubuntu, debian, windows, linux…
  (scanner.core.osfamily);
* host_results.os_source — откуда ОС: nmap (fingerprint -O), banner (баннеры
  сервисов -sV) или ssh (/etc/os-release по учётной записи).

Старые строки остаются с NULL: семейство для них выводится из os_guess при
чтении, так что переразбирать прошлые прогоны не нужно.

Revision ID: 0007
Revises: 0006
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE host_results ADD COLUMN os_family TEXT")
    op.execute("ALTER TABLE host_results ADD COLUMN os_source TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE host_results DROP COLUMN IF EXISTS os_source")
    op.execute("ALTER TABLE host_results DROP COLUMN IF EXISTS os_family")
