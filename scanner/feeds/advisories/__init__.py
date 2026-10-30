"""Бюллетени безопасности дистрибутивов: учёт бэкпортов (R2, docs/roadmap-v2.md).

Дистрибутивы переносят исправления в свои ревизии пакетов, не меняя версию
апстрима: ``openssl 1.1.1n-0+deb11u5`` закрывает CVE, которые «по версии
апстрима 1.1.1n» ещё открыты. Поэтому решение принимается по данным вендора:
(семейство, выпуск, пакет, CVE) → первая исправленная версия пакета, и точная
версия установленного пакета сравнивается с ней по правилам dpkg/rpm
(``scanner.feeds.vercmp``).

Источники — по файлу на семейство: ``debian`` (трекер безопасности),
``ubuntu`` (OVAL USN), ``redhat`` (OVAL v2; и для CentOS/Rocky/Alma/Oracle),
``alt`` (OVAL errata), ``astra`` и ``redos`` (OVAL вендора, файл/адрес задаёт
оператор). Загрузка — ``sync.sync_releases``, решение — ``assess``.
"""
from __future__ import annotations

from scanner.feeds.advisories import alt, astra, debian, redhat, redos, ubuntu
from scanner.feeds.advisories.base import Advisory, FamilySpec

FAMILIES: dict[str, FamilySpec] = {s.family: s for s in (
    debian.SPEC, ubuntu.SPEC, redhat.SPEC, alt.SPEC, astra.SPEC, redos.SPEC)}

# семейство хоста (scanner.core.osfamily) -> данные какого вендора
_BY_HOST = {hf: spec for spec in FAMILIES.values() for hf in spec.host_families}


def spec_for_host(os_family: str | None) -> FamilySpec | None:
    return _BY_HOST.get(os_family or "")


def host_release(os_family: str | None, version_id: str | None,
                 codename: str | None) -> tuple[FamilySpec, str] | None:
    """(данные вендора, выпуск) для хоста или None, если семейство не покрыто."""
    spec = spec_for_host(os_family)
    if spec is None:
        return None
    release = spec.release_of(version_id, codename)
    return (spec, release) if release else None


__all__ = ["FAMILIES", "Advisory", "FamilySpec", "host_release", "spec_for_host"]
