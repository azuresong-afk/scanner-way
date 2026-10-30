"""Управление активами: владельцы, критичность, теги и группы.

* assets — актив (хост) договора: адрес, имя, владелец, критичность
  (low < medium < high < critical), заметки; адрес уникален в договоре;
* asset_tags — теги актива;
* asset_groups — именованные группы активов договора (имя уникально в договоре);
* asset_group_members — связь «многие ко многим» актив ↔ группа.

Только новые таблицы. Критичность хранится текстом с CHECK; порядок значений
задаёт scanner.core.assets.CRITICALITY (его же использует R6).

Revision ID: 0010
Revises: 0009
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE assets (
            id              BIGSERIAL PRIMARY KEY,
            engagement_id   BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            address         INET NOT NULL,
            hostname        TEXT,
            owner           TEXT,
            criticality     TEXT NOT NULL DEFAULT 'medium'
                            CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
            notes           TEXT,
            created_by      BIGINT REFERENCES users(id),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (engagement_id, address)
        )
    """)
    op.execute("""
        CREATE TABLE asset_tags (
            asset_id  BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            tag       TEXT NOT NULL,
            PRIMARY KEY (asset_id, tag)
        )
    """)
    op.execute("CREATE INDEX idx_asset_tags_tag ON asset_tags(tag)")
    op.execute("""
        CREATE TABLE asset_groups (
            id              BIGSERIAL PRIMARY KEY,
            engagement_id   BIGINT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (engagement_id, name)
        )
    """)
    op.execute("""
        CREATE TABLE asset_group_members (
            asset_id  BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            group_id  BIGINT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
            PRIMARY KEY (asset_id, group_id)
        )
    """)
    op.execute("CREATE INDEX idx_asset_group_members_group "
               "ON asset_group_members(group_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS asset_group_members")
    op.execute("DROP TABLE IF EXISTS asset_groups")
    op.execute("DROP TABLE IF EXISTS asset_tags")
    op.execute("DROP TABLE IF EXISTS assets")
