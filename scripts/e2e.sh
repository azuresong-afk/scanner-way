#!/bin/sh
# Сквозной сценарий на живом стеке Docker: сборка образов, запуск в
# production-режиме, прогон по изолированной цели, отчёты, постраничные
# списки, восстановление прогона после падения API, резервная копия и
# восстановление из неё, проверка веб-интерфейса в браузере.
#
#   scripts/e2e.sh                 полный сценарий, после него стек удаляется
#   E2E_KEEP=1 scripts/e2e.sh      оставить стек и каталог для разбора
#
# Рабочая установка не затрагивается: проект копируется во временный каталог
# (E2E_DIR), там пишется свой .env со случайными секретами, стек поднимается
# под именем scanner-e2e на своих портах (E2E_WEB_PORT, по умолчанию 28080).
# Нужны: docker с compose v2.24.4+, python 3.12 с зависимостями проекта
# (pip install -e ".[dev]"), для проверки UI — node 18+ и пакет playwright
# с chromium (без них шаг UI пропускается с предупреждением, если не задано
# E2E_REQUIRE_UI=1).
#
# Дополнительный файл compose (например, локальная замена образов) —
# E2E_COMPOSE_EXTRA=/путь/к/файлу.yml.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_DIR="${E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/scanner-e2e.XXXXXX")}"
E2E_WEB_PORT="${E2E_WEB_PORT:-28080}"
E2E_API_PORT="${E2E_API_PORT:-28000}"
E2E_DB_PORT="${E2E_DB_PORT:-25432}"
ARTIFACTS="${E2E_ARTIFACTS:-$ROOT/e2e-artifacts}"
mkdir -p "$ARTIFACTS"

log() { echo "[e2e] $*"; }
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }

log "копия проекта -> $E2E_DIR"
mkdir -p "$E2E_DIR"
# web/dist и node_modules не нужны: образ web собирает интерфейс сам.
tar -C "$ROOT" --exclude=./.git --exclude=./.env --exclude=./data --exclude=./backups \
    --exclude='./data.before-restore-*' --exclude=./e2e-artifacts \
    --exclude=./web/node_modules --exclude=./web/dist --exclude='*/__pycache__' \
    -cf - . | tar -C "$E2E_DIR" -xf -
mkdir -p "$E2E_DIR/data"

ADMIN_PASSWORD="$(rand 18)"
OPERATOR_PASSWORD="$(rand 18)"
cat > "$E2E_DIR/.env" <<EOF
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=scanner
POSTGRES_USER=scanner
POSTGRES_PASSWORD=$(rand 24)
SCANNER_WEB_PORT=$E2E_WEB_PORT
SCANNER_API_PORT=$E2E_API_PORT
SCANNER_DB_PORT=$E2E_DB_PORT
SCANNER_API_SECRET=$(rand 48)
SCANNER_API_BOOTSTRAP_ADMIN=admin
SCANNER_API_BOOTSTRAP_PASSWORD=$ADMIN_PASSWORD
SCANNER_CREDENTIALS_KEY=$(rand 48)
SCANNER_BDU_AUTOLOAD=0
SCANNER_NUCLEI_UPDATE=${E2E_NUCLEI_UPDATE:-1}
SCANNER_API_RUN_HEARTBEAT_SECONDS=5
SCANNER_API_RUN_STALE_SECONDS=30
EOF

COMPOSE_FILE="docker-compose.yml:docker-compose.prod.yml:docker-compose.e2e.yml"
[ -n "${E2E_COMPOSE_EXTRA:-}" ] && COMPOSE_FILE="$COMPOSE_FILE:$E2E_COMPOSE_EXTRA"
export COMPOSE_FILE COMPOSE_PROJECT_NAME=scanner-e2e

cleanup() {
  status=$?
  cd "$E2E_DIR"
  docker compose logs --no-color > "$ARTIFACTS/compose.log" 2>&1 || true
  if [ "${E2E_KEEP:-0}" = "1" ]; then
    log "стек оставлен: cd $E2E_DIR && COMPOSE_FILE=$COMPOSE_FILE COMPOSE_PROJECT_NAME=scanner-e2e docker compose ps"
  else
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$E2E_DIR"
  fi
  [ $status -eq 0 ] && log "УСПЕХ" || log "ОШИБКА (код $status), логи: $ARTIFACTS/compose.log"
  exit $status
}
trap cleanup EXIT

cd "$E2E_DIR"
log "сборка и запуск стека (production + стенд-цель)"
if [ -n "${E2E_COMPOSE_EXTRA:-}" ]; then
  docker compose up -d --wait --wait-timeout "${E2E_WAIT_TIMEOUT:-900}"
else
  docker compose up -d --build --wait --wait-timeout "${E2E_WAIT_TIMEOUT:-900}"
fi
docker compose ps

export SCANNER_E2E_URL="http://127.0.0.1:$E2E_WEB_PORT"
export SCANNER_E2E_USER=admin SCANNER_E2E_PASSWORD="$ADMIN_PASSWORD"
export SCANNER_E2E_OP_PASSWORD="$OPERATOR_PASSWORD"
export SCANNER_E2E_DIR="$E2E_DIR" SCANNER_E2E_ARTIFACTS="$ARTIFACTS"
export SCANNER_E2E_TARGET=172.29.250.10 SCANNER_E2E_LAB=172.29.250.0/24

log "сценарий API (pytest -m e2e)"
( cd "$ROOT" && python3 -m pytest -m e2e -v -p no:cacheprovider tests/e2e \
    --junitxml="$ARTIFACTS/e2e-junit.xml" )

log "веб-интерфейс в браузере (playwright)"
if node -e "require('playwright')" >/dev/null 2>&1 || \
   (cd "$ROOT/web" && node -e "require('playwright')") >/dev/null 2>&1; then
  # в интерфейс входит оператор — тот, кто запускал прогоны
  ( cd "$ROOT/web" && SCANNER_E2E_USER=e2e-operator \
      SCANNER_E2E_PASSWORD="$OPERATOR_PASSWORD" node "$ROOT/scripts/e2e_ui.mjs" )
elif [ "${E2E_REQUIRE_UI:-0}" = "1" ]; then
  log "нет пакета playwright (npm i --no-save playwright && npx playwright install chromium)"
  exit 1
else
  log "ПРОПУЩЕНО: нет пакета playwright — проверка UI не выполнялась"
fi
