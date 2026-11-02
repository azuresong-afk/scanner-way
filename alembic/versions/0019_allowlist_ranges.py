"""Диапазоны адресов в allowlist.

Диапазон «10.0.0.1-10.0.0.50» хранится как минимальный набор подсетей CIDR
(гейт allowlist не меняется — проверяет только подсети). Чтобы показывать и
удалять диапазон одной строкой, у каждой его подсети в range_spec записан
исходный диапазон; у обычной записи (адрес или подсеть) range_spec — NULL.

Revision ID: 0019
Revises: 0018
"""
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE targets_allowlist ADD COLUMN range_spec TEXT")
    op.execute("CREATE INDEX idx_allowlist_range ON targets_allowlist(engagement_id, range_spec) "
               "WHERE range_spec IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_allowlist_range")
    op.execute("ALTER TABLE targets_allowlist DROP COLUMN IF EXISTS range_spec")
