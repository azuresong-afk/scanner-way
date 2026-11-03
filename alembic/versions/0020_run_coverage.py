"""Достоверность прогонов: покрытие, опции прогона, уверенность находок,
прогресс загрузки справочников.

* scan_run_coverage — что реально проверено на каждом хосте каждым модулем
  (completed / unreachable / timeout / no_credentials / not_applicable /
  skipped / error). По нему прогон получает статус partial («Частично»), а
  сравнение прогонов не считает исправленным то, что не проверялось.
  У прогонов до этой миграции строк нет — покрытие оценивается по
  host_results и модулям прогона (scanner.core.coverage.legacy_coverage).
* scan_runs.options — опции прогона (no_ping = nmap -Pn, профиль проверки).
* scan_runs.warnings — ограничения достоверности результата (нет бюллетеней
  выпуска ОС — «Бэкпорты не учтены», находки только по баннерам и т. п.).
* findings.confidence / findings.source — насколько находка подтверждена
  (high | medium | low) и чем: authenticated_package, vendor_advisory, banner,
  nuclei, config, credential, inventory. NULL у старых находок — источник
  выводится по модулю (scanner.core.confidence).
* feed_sync.progress_* — этап, записей загружено/всего и отметка времени
  текущей загрузки справочника (процент, скорость, ETA в интерфейсе);
  last_error_at — когда была последняя ошибка (старая ошибка не выдаётся
  за актуальную во время новой попытки).

Новый статус прогона partial — в downgrade становится done (в старой схеме
частичного статуса нет; причина остаётся в error_message).

Revision ID: 0020
Revises: 0019
"""
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_run_coverage (
            id          BIGSERIAL PRIMARY KEY,
            scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            host        INET NOT NULL,
            module      TEXT NOT NULL,
            status      TEXT NOT NULL CHECK (status IN ('completed', 'not_applicable',
                            'skipped', 'unreachable', 'no_credentials', 'timeout',
                            'error')),
            reason      TEXT,
            UNIQUE (scan_run_id, host, module)
        )""")
    op.execute("CREATE INDEX idx_coverage_run ON scan_run_coverage(scan_run_id)")
    op.execute("ALTER TABLE scan_runs ADD COLUMN options JSONB NOT NULL DEFAULT '{}'")
    op.execute("ALTER TABLE scan_runs ADD COLUMN warnings JSONB NOT NULL DEFAULT '[]'")
    op.execute("ALTER TABLE findings ADD COLUMN confidence TEXT")
    op.execute("ALTER TABLE findings ADD COLUMN source TEXT")
    op.execute("ALTER TABLE feed_sync ADD COLUMN progress_stage TEXT")
    op.execute("ALTER TABLE feed_sync ADD COLUMN progress_done BIGINT")
    op.execute("ALTER TABLE feed_sync ADD COLUMN progress_total BIGINT")
    op.execute("ALTER TABLE feed_sync ADD COLUMN progress_at TIMESTAMPTZ")
    op.execute("ALTER TABLE feed_sync ADD COLUMN last_error_at TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("UPDATE scan_runs SET status = 'done' WHERE status = 'partial'")
    op.execute("ALTER TABLE feed_sync DROP COLUMN IF EXISTS last_error_at")
    op.execute("ALTER TABLE feed_sync DROP COLUMN IF EXISTS progress_at")
    op.execute("ALTER TABLE feed_sync DROP COLUMN IF EXISTS progress_total")
    op.execute("ALTER TABLE feed_sync DROP COLUMN IF EXISTS progress_done")
    op.execute("ALTER TABLE feed_sync DROP COLUMN IF EXISTS progress_stage")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS source")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS confidence")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS warnings")
    op.execute("ALTER TABLE scan_runs DROP COLUMN IF EXISTS options")
    op.execute("DROP TABLE IF EXISTS scan_run_coverage")
