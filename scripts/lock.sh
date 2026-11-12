#!/usr/bin/env bash
# Фиксация версий Python-зависимостей (lock-файлы с хешами).
#
#   scripts/lock.sh                      — пересобрать lock после правки pyproject.toml
#                                           (уже закреплённые версии сохраняются)
#   scripts/lock.sh --upgrade            — обновить все пакеты до свежих версий
#   scripts/lock.sh --upgrade-package X  — обновить только пакет X
#
# requirements.lock     — зависимости приложения (из него ставит Dockerfile);
# requirements-dev.lock — то же + pytest/ruff/mypy/pip-audit (CI, разработка).
# Нужен uv (https://docs.astral.sh/uv/). CI проверяет, что lock-файлы совпадают
# с pyproject.toml (workflow checks, задание lock).
set -euo pipefail
cd "$(dirname "$0")/.."

common=(--universal --python-version 3.12 --generate-hashes --quiet)
uv pip compile pyproject.toml "${common[@]}" "$@" -o requirements.lock
uv pip compile pyproject.toml --extra dev -c requirements.lock "${common[@]}" "$@" -o requirements-dev.lock
