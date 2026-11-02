"""Проверка окружения перед стартом контейнера `app` (docker/entrypoint.sh).

В режиме SCANNER_ENV=production запуск с пустыми или шаблонными (CHANGE_ME)
секретами запрещён: API с временным ключом токенов «разлогинивает» всех при
каждом перезапуске, а без постоянного ключа шифрования сохранённые учётные
записи активов после перезапуска не расшифруются. Вне production те же
проблемы выводятся предупреждениями.

Запуск: python -m scanner.core.preflight  (код возврата 1 — старт запрещён).
"""
from __future__ import annotations

import os
import sys
from collections.abc import Mapping

PLACEHOLDER = "change_me"


def _placeholder(value: str) -> bool:
    return PLACEHOLDER in value.lower()


def check_env(env: Mapping[str, str]) -> tuple[list[str], list[str]]:
    """(ошибки, предупреждения) для окружения env."""
    problems: list[str] = []
    warnings: list[str] = []
    secret = env.get("SCANNER_API_SECRET", "")
    if not secret:
        problems.append("SCANNER_API_SECRET не задан: токены входа будут сбрасываться при "
                        "каждом перезапуске. Сгенерируйте: openssl rand -base64 48")
    elif _placeholder(secret):
        problems.append("SCANNER_API_SECRET содержит шаблон CHANGE_ME — замените его")
    elif len(secret) < 32:
        problems.append("SCANNER_API_SECRET короче 32 символов")
    pg = env.get("POSTGRES_PASSWORD", "")
    if not pg or _placeholder(pg):
        problems.append("POSTGRES_PASSWORD не задан или содержит шаблон CHANGE_ME")
    boot = env.get("SCANNER_API_BOOTSTRAP_PASSWORD", "")
    if boot and _placeholder(boot):
        problems.append("SCANNER_API_BOOTSTRAP_PASSWORD содержит шаблон CHANGE_ME — "
                        "задайте пароль первого администратора или уберите переменную")
    elif boot and len(boot) < 12:
        problems.append("SCANNER_API_BOOTSTRAP_PASSWORD короче 12 символов")
    key = env.get("SCANNER_CREDENTIALS_KEY", "")
    if key and _placeholder(key):
        problems.append("SCANNER_CREDENTIALS_KEY содержит шаблон CHANGE_ME")
    elif key and len(key) < 16:
        problems.append("SCANNER_CREDENTIALS_KEY короче 16 символов")
    elif not key:
        warnings.append("SCANNER_CREDENTIALS_KEY не задан: учётные записи активов шифруются "
                        "ключом SCANNER_API_SECRET, и его смена сделает их нечитаемыми. "
                        "Задайте отдельный ключ и храните его вместе с резервными копиями")
    workers = env.get("WEB_CONCURRENCY", "")
    if workers and workers != "1":
        problems.append("WEB_CONCURRENCY должен быть 1: прогоны, расписания и обновления "
                        "справочников исполняются в процессе API")
    return problems, warnings


def main(env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    production = env.get("SCANNER_ENV", "").lower() in {"production", "prod"}
    problems, warnings = check_env(env)
    for w in warnings:
        print(f"[preflight] ВНИМАНИЕ: {w}", file=sys.stderr)
    if not problems:
        return 0
    for p in problems:
        print(f"[preflight] {'ОШИБКА' if production else 'ВНИМАНИЕ'}: {p}", file=sys.stderr)
    if production:
        print("[preflight] SCANNER_ENV=production: старт остановлен. Исправьте .env и "
              "запустите снова (docker compose ... up -d).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
