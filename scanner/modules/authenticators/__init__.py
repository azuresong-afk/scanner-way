"""Бэкенды проверки учёток для модуля cred_audit.

Каждый адаптер реализует протокол `Authenticator` (`authenticate() -> AuthResult`)
для своих сервисов и лишь классифицирует ответ сервиса в `AuthOutcome`. Вся
защитная логика (лимиты попыток, backoff, остановка при блокировке, запись в
аудит без пароля) живёт в `cred_audit.py` — адаптеры её не дублируют.

По умолчанию подключаются только адаптеры, для которых в зависимостях есть
библиотечный клиент протокола (сейчас — SSH на paramiko). Для сервисов без
бэкенда композит возвращает `UNSUPPORTED`, и модуль корректно переходит к
следующей пробе, не делая попыток.
"""
from __future__ import annotations

from scanner.modules.authenticators.ssh import SERVICES as SSH_SERVICES
from scanner.modules.authenticators.ssh import SshPasswordAuthenticator
from scanner.modules.cred_audit import (
    Authenticator,
    AuthOutcome,
    AuthResult,
    Credential,
)


class CompositeAuthenticator:
    """Направляет проверку нужному адаптеру по имени сервиса.

    Для сервиса без зарегистрированного адаптера возвращает UNSUPPORTED —
    модуль cred_audit по этому исходу переходит к следующей пробе без попыток.
    """

    def __init__(self, backends: dict[str, Authenticator]):
        # имя сервиса -> адаптер
        self._backends = dict(backends)

    def authenticate(self, host: str, port: int, service: str,
                     credential: Credential, timeout: float) -> AuthResult:
        backend = self._backends.get(service.lower())
        if backend is None:
            return AuthResult(AuthOutcome.UNSUPPORTED, f"нет бэкенда для {service}")
        return backend.authenticate(host, port, service, credential, timeout)


def build_default_authenticator() -> CompositeAuthenticator:
    """Композит из адаптеров, для которых есть библиотечный клиент в зависимостях.

    paramiko — обязательная зависимость (используется auth_inventory), поэтому
    SSH-адаптер доступен всегда. Остальные сервисы -> UNSUPPORTED до появления
    соответствующего клиента."""
    backends: dict[str, Authenticator] = {}
    try:
        import paramiko  # noqa: F401
    except ImportError:
        pass
    else:
        ssh = SshPasswordAuthenticator()
        backends.update({name: ssh for name in SSH_SERVICES})
    return CompositeAuthenticator(backends)


__all__ = [
    "CompositeAuthenticator",
    "SshPasswordAuthenticator",
    "build_default_authenticator",
]
