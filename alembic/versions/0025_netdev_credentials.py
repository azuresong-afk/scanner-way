"""Учётки сетевого оборудования (netdev_audit).

* host_credentials.protocol — добавлены ``netssh`` (SSH в CLI коммутатора или
  маршрутизатора: Cisco, Juniper, MikroTik, Huawei, Eltex) и ``snmp`` (SNMPv2c
  community или SNMPv3 USM, только чтение). Существующие учётки не меняются.
* host_credentials.options — несекретные параметры учётки: платформа
  устройства (netssh) и версия SNMP / алгоритмы SNMPv3 (snmp). Секреты SNMP —
  как и прежде, только в secret_enc.

Revision ID: 0025
Revises: 0024
"""
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_protocol_check")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT "
               "host_credentials_protocol_check CHECK "
               "(protocol IN ('ssh', 'winrm', 'netssh', 'snmp'))")
    op.execute("ALTER TABLE host_credentials ADD COLUMN options JSONB NOT NULL "
               "DEFAULT '{}'::jsonb")


def downgrade() -> None:
    op.execute("DELETE FROM host_credentials WHERE protocol IN ('netssh', 'snmp')")
    op.execute("ALTER TABLE host_credentials DROP COLUMN IF EXISTS options")
    op.execute("ALTER TABLE host_credentials DROP CONSTRAINT IF EXISTS "
               "host_credentials_protocol_check")
    op.execute("ALTER TABLE host_credentials ADD CONSTRAINT "
               "host_credentials_protocol_check CHECK (protocol IN ('ssh', 'winrm'))")
