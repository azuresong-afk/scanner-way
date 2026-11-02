#!/bin/sh
# Самоподготовка окружения при старте контейнера:
#   миграции схемы -> одноразовая загрузка БДУ (если файл примонтирован) ->
#   обновление шаблонов Nuclei (по возможности) -> запуск API.
# Админа и роли создаёт само приложение при первом старте
# (SCANNER_API_BOOTSTRAP_ADMIN / SCANNER_API_BOOTSTRAP_PASSWORD, пока нет ни
# одного пользователя).
set -eu

# Секреты и параметры запуска. В SCANNER_ENV=production пустые или шаблонные
# (CHANGE_ME) секреты останавливают старт с понятной причиной в логе.
python -m scanner.core.preflight

# Миграции. База может подниматься дольше API (свой сервер, перезагрузка
# хоста) — несколько попыток, затем понятная ошибка вместо цикла перезапусков
# с трассировкой.
echo "[entrypoint] применяю миграции схемы БД (alembic upgrade head)..."
attempt=1
max_attempts="${SCANNER_DB_WAIT_ATTEMPTS:-30}"
until alembic upgrade head; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "[entrypoint] ОШИБКА: миграции не применены за $max_attempts попыток." >&2
    echo "[entrypoint] Проверьте, что БД доступна (POSTGRES_HOST/POSTGRES_PORT) и пароль" \
         "POSTGRES_PASSWORD совпадает с тем, с которым создавался том pg_data." >&2
    exit 1
  fi
  echo "[entrypoint] БД недоступна или миграция не прошла (попытка $attempt/$max_attempts), жду 2 с..." >&2
  attempt=$((attempt + 1))
  sleep 2
done

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

# Если для источника включено автообновление по расписанию (веб: «Справочники»),
# старт его не дублирует: БДУ только досевает пустую базу (метка выше), шаблоны
# Nuclei обновляет планировщик (пустой каталог шаблонов досевается и здесь).
# Ошибка проверки = расписание не включено.
feed_scheduled() {
  scanner --no-migrate feeds auto-enabled "$1" >/dev/null 2>&1
}

# Шаблоны Nuclei лежат в томах (см. docker-compose.yml) и переживают
# пересоздание контейнера; здесь они только обновляются.
NUCLEI_TEMPLATES_DIR="${HOME:-/root}/nuclei-templates"
if [ "${SCANNER_NUCLEI_UPDATE:-1}" = "1" ] && command -v nuclei >/dev/null 2>&1 \
   && [ -n "$(find "$NUCLEI_TEMPLATES_DIR" -name '*.yaml' -print -quit 2>/dev/null)" ] \
   && feed_scheduled nuclei; then
  echo "[entrypoint] шаблоны Nuclei обновляет расписание (раздел «Справочники»)"
elif [ "${SCANNER_NUCLEI_UPDATE:-1}" = "1" ] && command -v nuclei >/dev/null 2>&1; then
  echo "[entrypoint] обновляю шаблоны Nuclei (по возможности)..."
  if ! nuclei -update-templates -disable-update-check >/tmp/nuclei-update.log 2>&1; then
    echo "[entrypoint] шаблоны Nuclei не обновлены:" >&2
    tail -n 5 /tmp/nuclei-update.log >&2
  fi
fi
if command -v nuclei >/dev/null 2>&1 && \
   [ -z "$(find "$NUCLEI_TEMPLATES_DIR" -name '*.yaml' -print -quit 2>/dev/null)" ]; then
  echo "[entrypoint] ВНИМАНИЕ: шаблонов Nuclei нет — модуль «Поиск уязвимостей» не" \
       "сможет работать. Загрузите их: docker compose exec app nuclei -update-templates" >&2
fi

echo "[entrypoint] запускаю API на :8000 ..."
# Строго один процесс: прогоны, расписания, обновления справочников и
# уведомления исполняются фоновыми потоками внутри API.
exec uvicorn scanner.api.main:app --host 0.0.0.0 --port 8000 --workers 1
