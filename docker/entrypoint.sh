#!/bin/sh
# Самоподготовка окружения при старте контейнера:
#   миграции схемы -> одноразовая загрузка БДУ (если файл примонтирован) ->
#   обновление шаблонов Nuclei (по возможности) -> запуск API.
# Админа и роли создаёт само приложение при первом старте
# (SCANNER_API_BOOTSTRAP_ADMIN / SCANNER_API_BOOTSTRAP_PASSWORD, пока нет ни
# одного пользователя).
set -eu

echo "[entrypoint] применяю миграции схемы БД (alembic upgrade head)..."
alembic upgrade head

: "${BDU_FSTEC_FEED_PATH:=/data/bdu_fstec.xml}"
MARKER=/data/.bdu_loaded
if [ "${SCANNER_BDU_AUTOLOAD:-1}" = "1" ] && [ -f "$BDU_FSTEC_FEED_PATH" ] && [ ! -f "$MARKER" ]; then
  echo "[entrypoint] одноразовая загрузка выгрузки БДУ ФСТЭК из $BDU_FSTEC_FEED_PATH..."
  if scanner --no-migrate feeds sync-bdu --file "$BDU_FSTEC_FEED_PATH"; then
    touch "$MARKER" 2>/dev/null || true
  else
    echo "[entrypoint] ВНИМАНИЕ: загрузка БДУ не удалась; API стартует без неё" >&2
  fi
fi

if [ "${SCANNER_NUCLEI_UPDATE:-1}" = "1" ] && command -v nuclei >/dev/null 2>&1; then
  echo "[entrypoint] обновляю шаблоны Nuclei (по возможности)..."
  nuclei -update-templates -disable-update-check >/dev/null 2>&1 || \
    echo "[entrypoint] шаблоны Nuclei не обновлены (нет сети?) — не критично" >&2
fi

echo "[entrypoint] запускаю API на :8000 ..."
exec uvicorn scanner.api.main:app --host 0.0.0.0 --port 8000
