"""Модули прогона: порядок исполнения, движки поиска уязвимостей, спутники
и фабрики модулей (реестр по умолчанию)."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from sqlalchemy.orm import Session

from scanner.modules.base import ScanModule

# Порядок исполнения: discovery первым — его сервисы (ctx.services) нужны
# остальным модулям.
MODULE_ORDER: tuple[str, ...] = ("discovery", "vuln", "auth_inventory", "win_inventory",
                                 "netdev_audit", "config_audit", "password_policy",
                                 "db_audit",
                                 "cred_audit")

# Движки поиска уязвимостей (выбор оператора): сетевые проверки Nuclei без
# учётной записи и/или инвентаризация по учётной записи — пакеты Linux
# (auth_inventory), обновления/ПО Windows по WinRM (win_inventory) и сетевое
# оборудование по SSH-CLI/SNMP (netdev_audit). Каждый модуль инертен там, где у
# него нет подходящей учётки, поэтому в смешанной сети «По учётной записи»
# покрывает и Linux, и Windows, и коммутаторы/маршрутизаторы.
VULN_ENGINES: dict[str, tuple[str, ...]] = {
    "nuclei": ("vuln",),
    "credentialed": ("auth_inventory", "win_inventory", "netdev_audit"),
    "both": ("vuln", "auth_inventory", "win_inventory", "netdev_audit"),
}
# Модули, которые входят на хосты по учётным записям договора (ctx.credentials).
CREDENTIAL_MODULES = frozenset({"auth_inventory", "win_inventory", "netdev_audit",
                                "config_audit", "db_audit"})
# Модули-спутники: ставятся в прогон вместе с основным. password_policy оценивает
# парольную политику, которую собирает config_audit (ctx.host_policy_configs);
# сам по себе в сеть не ходит и без config_audit инертен.
# auth_inventory едет с config_audit всегда: раз оператор дал SSH-учётку, пакеты
# хоста сверяются с бюллетенями вендора (CVE → БДУ ФСТЭК) по той же учётке.
# Иначе при движке «Nuclei» + аудит конфигураций уязвимости ПО на хосте
# оставались непроверенными и единственным сигналом о пакетах был Lynis
# (PKGS-7392, без CVE/БДУ). Lynis/OpenSCAP — источник аудита конфигураций,
# не уязвимостей.
COMPANION_MODULES: dict[str, tuple[str, ...]] = {
    "config_audit": ("auth_inventory", "password_policy")}

ModuleFactory = Callable[[], ScanModule]


def default_module_registry(matcher: object | None = None) -> dict[str, ModuleFactory]:
    """Имя модуля -> фабрика. Импорт ленивый: модули тянут свои зависимости.

    matcher — слой сопоставления CVE/БДУ (feeds.matcher.VulnMatcher). Когда он
    задан, модуль vuln обогащает находки CVE/БДУ ФСТЭК, а auth_inventory
    сопоставляет с ними версии пакетов; без него (matcher=None)
    находки остаются без привязки к справочникам — поэтому в реальном прогоне
    RunService всегда передаёт matcher над справочниками из БД.
    """
    def discovery() -> ScanModule:
        from scanner.modules.discovery import DiscoveryModule
        return DiscoveryModule()

    def vuln() -> ScanModule:
        from scanner.modules.vuln import VulnModule
        return VulnModule(matcher=matcher)

    def auth_inventory() -> ScanModule:
        from scanner.core.sshexec import options_from_env
        from scanner.modules.auth_inventory import (
            AuthInventoryModule,
            AuthInventoryOptions,
        )
        return AuthInventoryModule(AuthInventoryOptions(ssh=options_from_env()),
                                   matcher=matcher, advisories=_advisory_store(matcher),
                                   fetch_advisories=_advisory_fetcher(matcher))

    def win_inventory() -> ScanModule:
        from scanner.core.winexec import options_from_env
        from scanner.modules.win_inventory import (
            WinInventoryModule,
            WinInventoryOptions,
        )
        return WinInventoryModule(WinInventoryOptions(winrm=options_from_env()),
                                  matcher=matcher)

    def netdev_audit() -> ScanModule:
        from scanner.modules.netdev_audit import NetdevAuditModule, options_from_env
        return NetdevAuditModule(options_from_env(), matcher=matcher)

    def config_audit() -> ScanModule:
        from scanner.modules.config_audit import ConfigAuditModule, options_from_env
        return ConfigAuditModule(options_from_env())

    def db_audit() -> ScanModule:
        from scanner.core.dbexec import options_from_env
        from scanner.modules.db_audit import DbAuditModule, DbAuditOptions
        return DbAuditModule(DbAuditOptions(db=options_from_env()), matcher=matcher)

    def password_policy() -> ScanModule:
        from scanner.modules.password_policy import PasswordPolicyModule
        return PasswordPolicyModule()

    def cred_audit() -> ScanModule:
        from scanner.modules.authenticators import build_default_authenticator
        from scanner.modules.cred_audit import CredentialAuditModule
        # Бэкенды проверки подключаются по умолчанию (SSH на paramiko); модуль всё
        # равно инертен без согласованного набора проверки (ctx.cred_candidates).
        return CredentialAuditModule(authenticator=build_default_authenticator())

    return {"discovery": discovery, "vuln": vuln, "auth_inventory": auth_inventory,
            "win_inventory": win_inventory, "netdev_audit": netdev_audit,
            "config_audit": config_audit,
            "password_policy": password_policy, "db_audit": db_audit,
            "cred_audit": cred_audit}


def _advisory_store(matcher: object | None):
    """Бюллетени дистрибутивов (R2) из той же БД, что и справочники matcher."""
    engine = getattr(getattr(matcher, "store", None), "engine", None)
    if engine is None:
        return None
    from scanner.feeds.advisories.store import SqlAdvisoryStore
    return SqlAdvisoryStore(engine)


def _advisory_fetcher(matcher: object | None):
    """Подгрузка бюллетеней выпусков ОС, встреченных в прогоне (см.
    feeds.advisories.ondemand). None — выключено (ADVISORY_ON_DEMAND=0) или нет БД."""
    from scanner.core.config import settings
    mode = (settings.advisory_on_demand or "auto").strip().lower()
    engine = getattr(getattr(matcher, "store", None), "engine", None)
    if engine is None or mode in ("0", "false", "no", "off"):
        return None
    from pathlib import Path

    from scanner.feeds.advisories.ondemand import AdvisoryFetcher
    from scanner.feeds.advisories.store import SqlAdvisoryStore

    def allow_network() -> bool:
        if mode in ("1", "true", "yes", "on"):
            return True
        # auto: согласие оператора = включённое автообновление бюллетеней
        from sqlalchemy import select

        from scanner.core.db import FeedSync
        with Session(engine) as s:
            return bool(s.scalar(select(FeedSync.enabled)
                                 .where(FeedSync.source == "advisories")))

    directory = Path(settings.advisory_dir) if settings.advisory_dir else None
    return AdvisoryFetcher(SqlAdvisoryStore(engine), directory=directory,
                           urls=settings.advisory_urls(), allow_network=allow_network)


def with_companions(names: Iterable[str], known: Iterable[str] | None = None) -> list[str]:
    """Модули прогона плюс их спутники (COMPANION_MODULES); known — реестр,
    спутник вне его не добавляется."""
    names = list(names)
    allowed = None if known is None else set(known)
    extra = [c for m in names for c in COMPANION_MODULES.get(m, ())
             if c not in names and (allowed is None or c in allowed)]
    return list(dict.fromkeys([*names, *extra]))


def order_modules(names: Iterable[str]) -> list[str]:
    """Уникальные имена модулей в порядке исполнения (неизвестные — в конце)."""
    uniq = list(dict.fromkeys(names))
    rank = {m: i for i, m in enumerate(MODULE_ORDER)}
    return sorted(uniq, key=lambda m: (rank.get(m, len(rank)), uniq.index(m)))
