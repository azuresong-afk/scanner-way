"""Факты прогона для профилей соответствия (R5).

Находки прогона хранят только нарушения: правило бенчмарка, которое прошло, в
них не видно. Чтобы мера получила статус «выполнена», нужно знать, что
проверка на хосте действительно выполнялась. Модули складывают такие факты в
`ScanContext.compliance_facts` (хост -> {ключ -> значение}), оркестратор
дополняет их тем, что видно по итогам прогона, и сохраняет вместе с
результатами соответствия (таблица compliance_facts, миграция 0015).

Ключи фактов хоста (все необязательны):
  * ``openscap`` — {"profile": id профиля XCCDF, "rules": {rule_id: result},
    "cis": {rule_id: {"refs": [пункты CIS], "title": заголовок}}}; result —
    pass | fail | notapplicable | error | unknown (notselected не хранится);
  * ``lynis`` — {"executed": [TEST-ID, …]} из report.dat (tests_executed);
  * ``password_policy`` — True: файлы парольной политики прочитаны и оценены;
  * ``windows_policy`` — {параметр: значение} (win_inventory, R3);
  * ``windows`` / ``linux_inventory`` — True: инвентаризация по учётной
    записи выполнена (обновления/пакеты хоста проверены);
  * ``network_vuln`` — True: сетевые проверки уязвимостей (Nuclei) по хосту;
  * ``discovery`` — True: хост просканирован discovery (известны его сервисы);
  * ``cred_audit`` — True: на хосте была хотя бы одна попытка проверки учёток.

Факты не содержат секретов и вывода целей — только идентификаторы правил,
результаты и значения параметров безопасности.
"""
from __future__ import annotations

import threading
from typing import Any

_LOCK = threading.Lock()

# Результаты XCCDF, которые имеют смысл для соответствия.
OPENSCAP_RESULTS = frozenset({"pass", "fail", "notapplicable", "error", "unknown"})


def record(facts: dict[str, dict[str, Any]], host: str, key: str, value: Any) -> None:
    """Потокобезопасно записать факт хоста (модули проверяют хосты параллельно)."""
    with _LOCK:
        facts.setdefault(host, {})[key] = value


def merge_run_facts(facts: dict[str, dict[str, Any]], *, completed: set[str],
                    discovered: set[str], inventory: dict[str, Any],
                    policy_hosts: set[str], targets: list[str]) -> dict[str, dict[str, Any]]:
    """Дополнить факты модулей тем, что видно по итогам прогона.

    completed — модули, отработавшие без ошибки; discovered — хосты, найденные
    discovery; inventory — ctx.inventory (хост -> HostInventory); policy_hosts —
    хосты с собранной парольной политикой (config_audit -> password_policy).
    """
    out = {h: dict(v) for h, v in facts.items()}

    def put(host: str, key: str, value: Any = True) -> None:
        out.setdefault(host, {})[key] = value

    if "discovery" in completed:
        for h in discovered:
            put(h, "discovery")
    if "vuln" in completed:
        # Nuclei проверяет хосты discovery, а без него — все цели прогона.
        for h in (discovered if "discovery" in completed else set(targets)):
            put(h, "network_vuln")
    for h, inv in inventory.items():
        put(h, "windows" if getattr(inv, "os_id", None) == "windows" else "linux_inventory")
    if "password_policy" in completed:
        for h in policy_hosts:
            put(h, "password_policy")
    return out
