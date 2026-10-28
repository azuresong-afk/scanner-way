"""Модуль 4: аудит учётных данных (контролируемый).

Назначение — выявить ОЧЕВИДНО слабые/дефолтные учётные записи на АВТОРИЗОВАННЫХ
хостах, по согласованию с заказчиком, как это делает credential check в
OpenVAS/Nessus. НЕ инструмент взлома.

Встроенные гарантии безопасности:
  * работает только по целям из allowlist (гарантируется оркестратором);
  * жёсткие лимиты попыток на учётку/хост из RateProfile;
  * экспоненциальная пауза и остановка при признаках блокировки аккаунта, чтобы
    не вызвать lockout/DoS;
  * без встроенных словарей — набор проверяемых учёток задаётся оператором
    осознанно и фиксируется в аудите;
  * каждая попытка пишется в ctx.audit.

Модуль включается только явным правом (не входит в operator по умолчанию).
"""
from __future__ import annotations

from scanner.modules.base import ScanContext, ScanModule


class CredentialAuditModule(ScanModule):
    name = "cred_audit"

    def run(self, ctx: ScanContext):
        # TODO (итерация 5): управляемая проверка слабых/дефолтных учёток по
        # согласованным протоколам (SSH/RDP/SMB/web/БД) с лимитами
        # ctx.rate.max_auth_attempts_per_target и backoff; стоп при lockout.
        raise NotImplementedError("cred_audit: контролируемый модуль — итерация 5")
