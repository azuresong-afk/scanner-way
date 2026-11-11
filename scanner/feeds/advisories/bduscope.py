"""Выпуски ОС, которые запись БДУ называет затронутыми.

В «Версия ПО» записи БДУ вместе с самим ПО перечислены дистрибутивы, где
вендор зарегистрировал уязвимость: «7.3 (РЕД ОС), до 14.8.2 (ImageMagick)».
Если запись называет семейство ОС хоста, но только другие его выпуски (на
хосте РЕД ОС 8, а в записи лишь РЕД ОС 7.3), то для выпуска хоста она не
говорит «уязвим»: это бюллетень другого выпуска.
"""
from __future__ import annotations

import re

from scanner.feeds.bdu_fstec import BduRecord, parse_bdu_versions
from scanner.feeds.cpe import normalize_name

# Семейство ОС хоста (scanner.core.osfamily) -> названия ОС в БДУ ФСТЭК.
BDU_OS_NAMES: dict[str, tuple[str, ...]] = {
    "redos": ("РЕД ОС",),
    "astra": ("Astra Linux Special Edition", "Astra Linux Common Edition"),
    "debian": ("Debian GNU/Linux",),
    "ubuntu": ("Ubuntu",),
    "rhel": ("Red Hat Enterprise Linux",),
}

_NUM = re.compile(r"\d+(?:\.\d+)*")


def _parts(version: str | None) -> tuple[int, ...] | None:
    m = _NUM.match((version or "").strip())
    if not m:
        return None
    parts = [int(x) for x in m.group(0).split(".")]
    while len(parts) > 1 and parts[-1] == 0:      # 8.0 -> 8
        parts.pop()
    return tuple(parts)


def same_release(bdu_version: str, host_version: str) -> bool:
    """«8.0» ~ «8», «1.7» ~ «1.7.5», «22.04 LTS» ~ «22.04»; «7.3» ≁ «8»."""
    a, b = _parts(bdu_version), _parts(host_version)
    if a is None or b is None:
        return False
    n = min(len(a), len(b))
    return a[:n] == b[:n]


def named_releases(rec: BduRecord, family: str) -> list[str] | None:
    """Выпуски семейства, перечисленные в записи.

    None — запись семейство не называет или называет без точного выпуска
    («до 7.2 Муром», «-»): по такой записи о выпуске хоста судить нельзя."""
    names = {normalize_name(n) for n in BDU_OS_NAMES.get(family, ())}
    if not names:
        return None
    out: list[str] = []
    for spec in parse_bdu_versions(rec.versions):
        if normalize_name(spec.software) not in names:
            continue
        if spec.exact is None or _parts(spec.exact) is None:
            return None
        out.append(spec.exact)
    return out or None


def other_release_only(rec: BduRecord, family: str, host_version: str | None) -> bool:
    """Запись называет семейство ОС хоста, но только другие выпуски."""
    if not host_version or _parts(host_version) is None:
        return False
    named = named_releases(rec, family)
    return named is not None and not any(same_release(v, host_version) for v in named)


def names_release(rec: BduRecord, family: str, host_version: str | None) -> bool:
    """Запись прямо называет выпуск хоста («8.0 (РЕД ОС)» для РЕД ОС 8)."""
    if not host_version:
        return False
    named = named_releases(rec, family)
    return named is not None and any(same_release(v, host_version) for v in named)
