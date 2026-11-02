#!/bin/sh
# Резервная копия сканера: база PostgreSQL (pg_dump, формат custom) и каталог
# ./data (known_hosts SSH, бюллетени, метка загрузки БДУ, файлы справочников).
#
#   scripts/backup.sh [каталог]       по умолчанию ./backups/ГГГГ-ММ-ДД_ЧЧММСС
#
# Работает при запущенном стеке (сервис db должен быть запущен); прогоны не
# останавливаются — pg_dump снимает согласованный снимок.
# ВАЖНО: файл .env (SCANNER_CREDENTIALS_KEY / SCANNER_API_SECRET) в копию НЕ
# входит — храните его отдельно и надёжно: без того же ключа сохранённые учётные
# записи активов из копии не расшифруются.
# Для production-файла compose задайте COMPOSE_FILE (см. docs/INSTALL.md, раздел 16).
set -eu

cd "$(dirname "$0")/.."
DEST="${1:-backups/$(date +%Y-%m-%d_%H%M%S)}"
mkdir -p "$DEST"

# Имя БД и пользователь — из окружения контейнера db (как их задал .env).
echo "[backup] база данных -> $DEST/db.dump"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner' > "$DEST/db.dump"
# pg_dump с ошибкой оставит пустой/обрезанный файл — проверяем оглавлением.
docker compose exec -T db pg_restore --list < "$DEST/db.dump" > /dev/null

echo "[backup] каталог data -> $DEST/data.tar.gz"
tar -czf "$DEST/data.tar.gz" -C . data

REV=$(docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"' | tr -d '[:space:]')
{
  echo "created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "alembic_revision=$REV"
  echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$DEST/manifest.txt"
( cd "$DEST" && sha256sum db.dump data.tar.gz > SHA256SUMS )

echo "[backup] готово: $DEST ($(du -sh "$DEST" | cut -f1)), миграция $REV"
echo "[backup] не забудьте отдельно сохранить .env (ключи шифрования)."
