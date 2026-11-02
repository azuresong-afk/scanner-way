#!/bin/sh
# Восстановление из резервной копии scripts/backup.sh.
#
#   scripts/restore.sh КАТАЛОГ_КОПИИ --yes
#
# Что делает: проверяет контрольные суммы, останавливает app и web (чтобы
# никто не писал в БД), пересоздаёт базу, загружает дамп, возвращает каталог
# ./data (текущий сохраняется рядом как data.before-restore-*), запускает app
# и web. Если копия старше текущей версии, недостающие миграции применит app
# при старте. ТЕКУЩИЕ ДАННЫЕ БД ЗАМЕНЯЮТСЯ — поэтому нужен флаг --yes.
# .env должен содержать тот же SCANNER_CREDENTIALS_KEY / SCANNER_API_SECRET,
# что и при создании копии, иначе учётные записи активов не расшифруются.
set -eu

cd "$(dirname "$0")/.."
SRC="${1:-}"
if [ -z "$SRC" ] || [ ! -f "$SRC/db.dump" ]; then
  echo "использование: scripts/restore.sh КАТАЛОГ_КОПИИ --yes (нет $SRC/db.dump)" >&2
  exit 2
fi
if [ "${2:-}" != "--yes" ]; then
  echo "Восстановление ЗАМЕНИТ текущую базу данными из $SRC." >&2
  echo "Повторите с флагом --yes: scripts/restore.sh $SRC --yes" >&2
  exit 2
fi

if [ -f "$SRC/SHA256SUMS" ]; then
  echo "[restore] проверяю контрольные суммы"
  ( cd "$SRC" && sha256sum -c --quiet SHA256SUMS )
fi

echo "[restore] останавливаю app и web"
docker compose stop app web
docker compose up -d db
until docker compose exec -T db sh -c 'pg_isready -U "$POSTGRES_USER" -d postgres' >/dev/null 2>&1; do
  sleep 1
done

echo "[restore] пересоздаю базу и загружаю дамп"
docker compose exec -T db sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --exit-on-error' < "$SRC/db.dump"

if [ -f "$SRC/data.tar.gz" ]; then
  if [ -d data ]; then
    KEEP="data.before-restore-$(date +%Y%m%d_%H%M%S)"
    echo "[restore] текущий ./data сохранён как ./$KEEP"
    mv data "$KEEP"
  fi
  tar -xzf "$SRC/data.tar.gz" -C .
fi

echo "[restore] запускаю app и web (миграции применятся при старте app)"
docker compose up -d app web
echo "[restore] готово. Проверьте: docker compose ps (app — healthy) и вход в веб-интерфейс."
