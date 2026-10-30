"""Адаптер проверки учётки по SSH (бэкенд для модуля cred_audit).

Тонкий адаптер к paramiko: делает РОВНО одну попытку входа паролем и однозначно
классифицирует ответ сервиса в AuthOutcome. Вся защитная логика (лимиты,
backoff, остановка при блокировке, запись в аудит без пароля) остаётся в
`cred_audit.py`; адаптер её не дублирует и не обходит.

Безопасность:
- секрет (пароль) не логируется, не кладётся в находку и в текст исключений —
  наружу уходит только класс исключения;
- используется ТОЛЬКО переданный модулем таймаут (connect/banner/auth), чтобы
  уважать выбранный профиль нагрузки;
- проверка только пароля: подбор ключей и агент отключены
  (`allow_agent=False`, `look_for_keys=False`).
"""
from __future__ import annotations

from scanner.modules.cred_audit import AuthOutcome, AuthResult, Credential

# Имена сервисов (из discovery), которые обслуживает этот адаптер.
SERVICES: frozenset[str] = frozenset({"ssh"})

# Подстроки в ответе сервера, означающие блокировку/лимит попыток → СТОП по хосту.
_LOCKOUT_HINTS = ("too many authentication failures", "too many bad auth",
                  "account locked", "maximum authentication attempts")


class SshPasswordAuthenticator:
    """Проверка пары логин/пароль по SSH через paramiko (одна попытка)."""

    def authenticate(self, host: str, port: int, service: str,
                     credential: Credential, timeout: float) -> AuthResult:
        try:
            import paramiko
        except ImportError:
            return AuthResult(AuthOutcome.UNSUPPORTED, "paramiko не установлен")

        client = paramiko.SSHClient()
        # Проверка учётки, а не передача данных: ключ хоста не закрепляем.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host, port=port, username=credential.username,
                password=credential.secret, allow_agent=False, look_for_keys=False,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        except paramiko.AuthenticationException:
            return AuthResult(AuthOutcome.FAILURE, "сервер отклонил учётку")
        except paramiko.SSHException as e:
            msg = str(e).lower()
            if any(h in msg for h in _LOCKOUT_HINTS):
                return AuthResult(AuthOutcome.LOCKOUT, "сервер сообщил о лимите попыток")
            return AuthResult(AuthOutcome.ERROR, f"ssh: {type(e).__name__}")
        except OSError as e:
            # соединение не установлено (отказ/таймаут/сеть) — не аутентификация
            return AuthResult(AuthOutcome.ERROR, f"сеть: {type(e).__name__}")
        except Exception as e:  # noqa: BLE001 — любой иной сбой классифицируем как ошибку
            return AuthResult(AuthOutcome.ERROR, f"{type(e).__name__}")
        else:
            return AuthResult(AuthOutcome.SUCCESS, "вход выполнен")
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001, S110 — закрытие соединения не должно падать
                pass
