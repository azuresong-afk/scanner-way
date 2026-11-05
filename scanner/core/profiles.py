"""Готовые профили проверки и итоговый состав прогона до запуска.

Оператор выбирает «что проверить», а не набор внутренних модулей: так не
получится «думал, что запустил полную проверку, а выбрал только
discovery/auth_inventory/win_inventory». Перед запуском показывается итоговый
список модулей (со спутниками) и что каждый проверит — и чего НЕ проверит
(нет учётки нужного протокола, модуль неприменим).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from scanner.core.naming import MODULE_TITLES


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    title: str
    description: str
    modules: tuple[str, ...]
    needs: tuple[str, ...] = ()          # протоколы учёток: ssh | winrm | netssh | snmp


PROFILES: dict[str, Profile] = {p.id: p for p in (
    Profile("linux_full", "Полная проверка Linux",
            "Обнаружение хостов и сервисов, сетевая проверка (Nuclei, баннеры), пакеты по "
            "SSH с учётом бюллетеней вендора (CVE/БДУ ФСТЭК, ядро), аудит конфигурации "
            "(OpenSCAP/Lynis) и парольной политики. Нужна SSH-учётка.",
            ("discovery", "vuln", "auth_inventory", "config_audit", "password_policy"),
            ("ssh",)),
    Profile("windows_full", "Полная проверка Windows",
            "Обнаружение хостов и сервисов, сетевая проверка (Nuclei, баннеры), "
            "установленные обновления и ПО по WinRM (MSRC, CVE/БДУ ФСТЭК). Нужна "
            "WinRM-учётка.",
            ("discovery", "vuln", "win_inventory"), ("winrm",)),
    Profile("network_devices", "Сетевое оборудование",
            "Коммутаторы, маршрутизаторы и межсетевые экраны (Cisco, Juniper, MikroTik, "
            "Huawei, Eltex): версия ОС устройства → CVE/БДУ ФСТЭК и аудит конфигурации "
            "(Telnet/HTTP, SNMP, пароли, AAA, журналы, NTP). Нужна учётка сетевого "
            "устройства: SSH только на просмотр (версия и конфигурация) или SNMP "
            "(только версия).",
            ("discovery", "netdev_audit"), ("netssh",)),
    Profile("network", "Только сетевая проверка",
            "Обнаружение и проверка без учётной записи: шаблоны Nuclei и версии из "
            "баннеров. Бэкпорты дистрибутивов не учитываются — находки по баннерам "
            "имеют низкую уверенность.",
            ("discovery", "vuln")),
    Profile("discovery", "Только обнаружение",
            "Живые хосты, открытые порты, сервисы и ОС (nmap). Уязвимости не ищутся.",
            ("discovery",)),
)}

# Что модуль НЕ проверит без учётки/как ограничен — для предупреждений до запуска.
_NEEDS = {"auth_inventory": "ssh", "config_audit": "ssh", "win_inventory": "winrm",
          "netdev_audit": "netdev"}
# «netdev» — любая учётка сетевого оборудования: SSH-CLI или SNMP.
_NETDEV = frozenset({"netssh", "snmp"})
_NEED_LABEL = {"ssh": "SSH", "winrm": "WinRM", "netdev": "сетевого оборудования (SSH/SNMP)"}


def _has(need: str, protocols: set[str]) -> bool:
    return bool(protocols & _NETDEV) if need == "netdev" else need in protocols


@dataclass(slots=True)
class PlannedModule:
    name: str
    title: str
    added_as_companion: bool = False
    note: str | None = None


@dataclass(slots=True)
class RunPlan:
    modules: list[PlannedModule] = field(default_factory=list)
    removed: list[PlannedModule] = field(default_factory=list)   # неприменимые
    warnings: list[str] = field(default_factory=list)
    full_check: bool = False

    @property
    def names(self) -> list[str]:
        return [m.name for m in self.modules]

    def to_dict(self) -> dict:
        def m(x: PlannedModule) -> dict:
            return {"name": x.name, "title": x.title, "companion": x.added_as_companion,
                    "note": x.note}
        return {"modules": [m(x) for x in self.modules],
                "removed": [m(x) for x in self.removed],
                "warnings": self.warnings, "full_check": self.full_check}


def plan_modules(requested: Iterable[str], *, protocols: set[str],
                 engine_modules: Iterable[str] = (), known: Iterable[str] | None = None,
                 no_ping: bool = False) -> RunPlan:
    """Итоговый состав прогона.

    requested — модули после выбора движка/профиля; engine_modules — те из них,
    что добавлены выбором движка/профиля (их можно убрать как неприменимые:
    WinRM-инвентаризация без WinRM-учётки); protocols — протоколы выбранных
    учёток (ssh, winrm)."""
    from scanner.core.orchestrator import (
        COMPANION_MODULES,
        order_modules,
        with_companions,
    )
    req = list(dict.fromkeys(requested))
    auto = set(engine_modules)
    plan = RunPlan()
    keep = []
    for name in req:
        need = _NEEDS.get(name)
        if need and not _has(need, protocols) and name in auto and (
                protocols - ({need} if need != "netdev" else _NETDEV)):
            plan.removed.append(PlannedModule(
                name, MODULE_TITLES.get(name, name),
                note=("нет учётки WinRM — Windows-хосты этим модулем не проверяются"
                      if need == "winrm" else
                      "нет учётки сетевого оборудования — коммутаторы и маршрутизаторы "
                      "этим модулем не проверяются" if need == "netdev" else
                      "нет SSH-учётки — Linux-хосты этим модулем не проверяются")))
            continue
        keep.append(name)
    companions = {c for m in keep for c in COMPANION_MODULES.get(m, ())}
    final = order_modules(with_companions(keep, known))
    for name in final:
        need = _NEEDS.get(name)
        note = None
        if need and not _has(need, protocols):
            note = (f"нет учётки {_NEED_LABEL[need]} — модуль не "
                    "сможет войти на хосты, проверка будет неполной")
            plan.warnings.append(f"{MODULE_TITLES.get(name, name)}: {note}")
        plan.modules.append(PlannedModule(name, MODULE_TITLES.get(name, name),
                                          added_as_companion=name in companions
                                          and name not in req, note=note))
    names = set(final)
    if "vuln" in names and not names & {"auth_inventory", "win_inventory", "netdev_audit"}:
        plan.warnings.append("Нет проверки по учётной записи: уязвимости определяются только "
                             "по сети (Nuclei, баннеры) — бэкпорты дистрибутивов не "
                             "учитываются, пакеты и конфигурация не проверяются.")
    if names <= {"discovery"}:
        plan.warnings.append("Выбрано только обнаружение: уязвимости не проверяются.")
    if "discovery" not in names:
        plan.warnings.append("Без обнаружения (discovery) недоступность хостов не "
                             "определяется заранее — модули попробуют все цели.")
    if no_ping:
        plan.warnings.append("Сканирование без ping (-Pn): каждый адрес считается "
                             "включённым — выключенные хосты сканируются по портам до "
                             "таймаута, прогон дольше.")
    plan.full_check = (
        {"discovery", "vuln"} <= names
        and (({"auth_inventory", "config_audit"} <= names and "ssh" in protocols)
             or ("win_inventory" in names and "winrm" in protocols)
             or ("netdev_audit" in names and bool(protocols & _NETDEV))))
    return plan
