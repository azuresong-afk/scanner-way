"""Покрытие прогона: что реально проверено на каждом хосте каждым модулем.

Без этого прогон с недоступным хостом или с таймаутом SSH выглядел как обычный
успешный («done», ноль находок), а сравнение прогонов считало исправленным всё,
что просто не проверялось.

Статусы (хост × модуль):
  completed       — модуль отработал на хосте;
  not_applicable  — модуль к хосту неприменим (Windows-инвентаризация на Linux);
  skipped         — не выполнялся осознанно (прогон остановлен, нет набора
                    проверки учёток, нет данных от модуля-источника);
  unreachable     — хост/порт недоступен (не ответил discovery, SSH закрыт);
  no_credentials  — модулю нужна учётная запись, а для хоста её нет;
  timeout         — истёк таймаут (SSH/WinRM/команда);
  error           — ошибка модуля или входа (учётка отклонена, нет sudo…).

Пробелы покрытия (unreachable, no_credentials, timeout, error) делают прогон
«частично выполненным» (partial); если ни на одном хосте не выполнено ничего —
прогон «failed» с понятной причиной («Хост недоступен, проверка не выполнена»).
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

COMPLETED = "completed"
NOT_APPLICABLE = "not_applicable"
SKIPPED = "skipped"
UNREACHABLE = "unreachable"
NO_CREDENTIALS = "no_credentials"
TIMEOUT = "timeout"
ERROR = "error"

STATUSES = (COMPLETED, NOT_APPLICABLE, SKIPPED, UNREACHABLE, NO_CREDENTIALS, TIMEOUT,
            ERROR)
GAP_STATUSES = frozenset({UNREACHABLE, NO_CREDENTIALS, TIMEOUT, ERROR})
# «Хуже» перекрывает «лучше», если модуль сообщил о хосте несколько раз.
_RANK = {COMPLETED: 0, NOT_APPLICABLE: 1, SKIPPED: 2, NO_CREDENTIALS: 3,
         UNREACHABLE: 4, TIMEOUT: 5, ERROR: 6}

STATUS_LABELS = {
    COMPLETED: "выполнено",
    NOT_APPLICABLE: "неприменимо",
    SKIPPED: "пропущено",
    UNREACHABLE: "хост недоступен",
    NO_CREDENTIALS: "нет учётной записи",
    TIMEOUT: "таймаут",
    ERROR: "ошибка",
}

# Модули, которые входят на хост по учётной записи (их пробелы = нет
# пакетного аудита / аудита конфигурации).
AUTH_MODULES = frozenset({"auth_inventory", "win_inventory", "config_audit"})

MSG_HOST_DOWN = "Хост недоступен, проверка не выполнена"
REC_HOST_DOWN = ("Хост не ответил на обнаружение (ICMP/TCP). Проверьте, что он "
                 "включён и доступен из сети сканера. Если хост блокирует ICMP, "
                 "запустите прогон с опцией «Сканировать без проверки ping (-Pn)».")


@dataclass(slots=True)
class CoverageEntry:
    host: str
    module: str
    status: str
    reason: str | None = None        # короткая причина / рекомендация для оператора

    @property
    def is_gap(self) -> bool:
        return self.status in GAP_STATUSES


def _host(h: str) -> str:
    try:
        return str(ipaddress.ip_address(str(h).strip()))
    except ValueError:
        return str(h)


class Coverage:
    """Покрытие прогона: (хост, модуль) -> CoverageEntry. Потокобезопасно для
    записей из пула модуля (присваивание в dict атомарно в CPython)."""

    def __init__(self, entries: Iterable[CoverageEntry] = ()):
        self._e: dict[tuple[str, str], CoverageEntry] = {}
        for e in entries:
            self._e[(_host(e.host), e.module)] = e

    def mark(self, host: str, module: str, status: str, reason: str | None = None, *,
             force: bool = False) -> None:
        if status not in _RANK:
            raise ValueError(f"unknown coverage status: {status}")
        key = (_host(host), module)
        cur = self._e.get(key)
        if cur is not None and not force and _RANK[cur.status] > _RANK[status]:
            return
        self._e[key] = CoverageEntry(key[0], module, status,
                                     (reason or None) and str(reason)[:1000])

    def get(self, host: str, module: str) -> CoverageEntry | None:
        return self._e.get((_host(host), module))

    def status(self, host: str, module: str) -> str | None:
        e = self.get(host, module)
        return e.status if e else None

    def covered(self, host: str, module: str) -> bool:
        """Модуль действительно проверил хост — отсутствие находки значимо."""
        return self.status(host, module) == COMPLETED

    def entries(self) -> list[CoverageEntry]:
        return sorted(self._e.values(), key=lambda e: (_ip_key(e.host), e.module))

    def hosts(self) -> list[str]:
        return sorted({h for h, _ in self._e}, key=_ip_key)

    def modules(self) -> list[str]:
        return sorted({m for _, m in self._e})

    def __bool__(self) -> bool:
        return bool(self._e)

    def __len__(self) -> int:
        return len(self._e)

    # --- итоги ---
    def gaps(self) -> list[CoverageEntry]:
        return [e for e in self.entries() if e.is_gap]

    def completed_hosts(self) -> set[str]:
        return {h for (h, _), e in self._e.items() if e.status == COMPLETED}

    def host_status(self, host: str) -> str:
        """Сводный статус хоста: checked | partial | unreachable | not_checked."""
        es = [e for (h, _), e in self._e.items() if h == _host(host)]
        if not es:
            return "not_checked"
        if all(e.status == UNREACHABLE for e in es):
            return "unreachable"
        if not any(e.status == COMPLETED for e in es):
            return "not_checked"
        return "partial" if any(e.is_gap for e in es) else "checked"

    def summary(self) -> dict:
        hosts = self.hosts()
        per = {h: self.host_status(h) for h in hosts}
        counts = {s: 0 for s in STATUSES}
        for e in self._e.values():
            counts[e.status] += 1
        return {
            "hosts": len(hosts),
            "hosts_checked": sum(1 for v in per.values() if v == "checked"),
            "hosts_partial": sum(1 for v in per.values() if v == "partial"),
            "hosts_unreachable": sum(1 for v in per.values() if v == "unreachable"),
            "hosts_not_checked": sum(1 for v in per.values() if v == "not_checked"),
            "counts": counts,
            "gaps": len(self.gaps()),
            "auth_gaps": sum(1 for e in self.gaps() if e.module in AUTH_MODULES),
        }

    def to_dicts(self) -> list[dict]:
        return [{"host": e.host, "module": e.module, "status": e.status,
                 "label": STATUS_LABELS[e.status], "reason": e.reason}
                for e in self.entries()]


def _ip_key(h: str):
    try:
        ip = ipaddress.ip_address(h)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


# ---------- итог прогона ----------
def run_verdict(cov: Coverage, targets: Iterable[str]) -> tuple[str, str | None]:
    """(статус, сообщение) по покрытию: done | partial | failed.

    failed — ни на одном хосте ничего не проверено (все недоступны);
    partial — есть пробелы покрытия; done — всё применимое выполнено."""
    targets = [_host(t) for t in targets]
    if not cov:
        return "done", None
    checked = cov.completed_hosts()
    down = [h for h in targets if cov.host_status(h) == "unreachable"]
    if not checked:
        if targets and len(down) == len(targets):
            if len(targets) == 1:
                return "failed", f"{MSG_HOST_DOWN}: {targets[0]} не ответил. {REC_HOST_DOWN}"
            return "failed", (f"Ни один из {len(targets)} хостов не ответил — проверка не "
                              f"выполнена. {REC_HOST_DOWN}")
        return "failed", "Проверка не выполнена ни на одном хосте: " + describe_gaps(cov)
    gaps = cov.gaps()
    if not gaps:
        return "done", None
    return "partial", "Прогон выполнен частично: " + describe_gaps(cov)


def describe_gaps(cov: Coverage, limit: int = 6) -> str:
    """Пробелы покрытия одной строкой для пользователя."""
    from scanner.core.naming import MODULE_TITLES
    parts = []
    for e in cov.gaps()[:limit]:
        what = MODULE_TITLES.get(e.module, e.module)
        parts.append(f"{e.host} — {what}: {STATUS_LABELS[e.status]}"
                     + (f" ({e.reason})" if e.reason else ""))
    rest = len(cov.gaps()) - limit
    if rest > 0:
        parts.append(f"и ещё {rest}")
    return "; ".join(parts)


# ---------- покрытие старых прогонов (до миграции 0020) ----------
def legacy_coverage(status: str, modules: Iterable[str], targets: Iterable[str],
                    discovered: Iterable[str]) -> Coverage:
    """Оценка покрытия прогона без сохранённого покрытия: модули прогона на
    хостах, которые нашёл discovery (или на всех целях-адресах, если discovery
    не выполнялся). Неуспешные прогоны считаются непокрытыми."""
    cov = Coverage()
    if status not in ("done", "partial"):
        return cov
    found = {_host(h) for h in discovered}
    mods = list(modules)
    hosts = set(found)
    if "discovery" not in mods:
        from scanner.core.targetspec import is_range, parse_target, range_hosts
        for t in targets:
            t = str(t).strip()
            try:
                if is_range(t):
                    rng = parse_target(t)
                    if rng.num_addresses <= 4096:
                        hosts.update(range_hosts(rng))
                    continue
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                continue
            if net.num_addresses <= 4098:
                hosts.update(str(h) for h in (net.hosts() if net.num_addresses > 1
                                              else [net.network_address]))
    for h in hosts:
        for m in mods:
            cov.mark(h, m, COMPLETED)
    return cov


# ---------- сопоставимость прогонов ----------
@dataclass(slots=True)
class Comparability:
    level: str                       # same | partial | none
    common_hosts: list[str]
    common_modules: list[str]
    only_baseline_hosts: list[str]
    only_current_hosts: list[str]
    only_baseline_modules: list[str]
    only_current_modules: list[str]
    warnings: list[str]

    def to_dict(self) -> dict:
        return {"level": self.level, "common_hosts": self.common_hosts,
                "common_modules": self.common_modules,
                "only_baseline_hosts": self.only_baseline_hosts,
                "only_current_hosts": self.only_current_hosts,
                "only_baseline_modules": self.only_baseline_modules,
                "only_current_modules": self.only_current_modules,
                "warnings": self.warnings}


def comparability(baseline: Coverage, current: Coverage) -> Comparability:
    """Насколько прогоны сравнимы: общие проверенные хосты и модули."""
    bp = {(e.host, e.module) for e in baseline.entries() if e.status == COMPLETED}
    cp = {(e.host, e.module) for e in current.entries() if e.status == COMPLETED}
    bh, ch = {h for h, _ in bp}, {h for h, _ in cp}
    bm, cm = {m for _, m in bp}, {m for _, m in cp}
    common = bp & cp
    hosts = sorted({h for h, _ in common}, key=_ip_key)
    mods = sorted({m for _, m in common})
    warnings = []
    if not common:
        level = "none"
        warnings.append("Прогоны несопоставимы: нет ни одного хоста, проверенного одним и "
                        "тем же модулем в обоих прогонах. Исправленные и повторные находки "
                        "не определяются.")
    elif bp == cp:
        level = "same"
    else:
        level = "partial"
        if bh - ch:
            warnings.append(f"Хосты, не проверенные в текущем прогоне ({len(bh - ch)}): их "
                            "находки не считаются исправленными.")
        if ch - bh:
            warnings.append(f"Хосты, не проверенные в базовом прогоне ({len(ch - bh)}): их "
                            "находки не считаются повторными (regression).")
        if bm != cm:
            warnings.append("Разный набор модулей: сравниваются только модули, выполненные "
                            "в обоих прогонах (" + ", ".join(mods) + ").")
        if bh == ch and bm == cm:
            warnings.append("Часть проверок хостов выполнена только в одном из прогонов "
                            "(недоступность, таймаут или нет учётки) — по ним сравнение "
                            "не выполняется.")
    return Comparability(level, hosts, mods,
                         sorted(bh - ch, key=_ip_key), sorted(ch - bh, key=_ip_key),
                         sorted(bm - cm), sorted(cm - bm), warnings)


def coverage_from_rows(rows: Iterable[Mapping | object]) -> Coverage:
    cov = Coverage()
    for r in rows:
        get = (r.get if isinstance(r, Mapping) else lambda k, r=r: getattr(r, k))
        cov.mark(str(get("host")), get("module"), get("status"), get("reason"), force=True)
    return cov
