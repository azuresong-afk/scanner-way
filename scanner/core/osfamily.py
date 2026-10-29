"""Семейство ОС хоста: Astra Linux, РЕД ОС, Ubuntu, Debian, Windows…

Три источника, по убыванию точности:

* ``ssh`` — /etc/os-release, прочитанный на хосте учётным движком (auth_inventory);
* ``banner`` — дистрибутив из баннеров сервисов nmap -sV («OpenSSH 8.9p1 Ubuntu…»,
  «Apache (Debian)»);
* ``nmap`` — fingerprint стека nmap -O. Он различает ядро (Linux / Windows / BSD…),
  но не дистрибутив: Astra и Debian для него одинаковы — «Linux 4.15 - 5.8».

Ключ семейства хранится в host_results.os_family; подпись — ``family_label``.
"""
from __future__ import annotations

import re

# Ключ семейства без уточнения дистрибутива.
GENERIC_LINUX = "linux"
UNKNOWN = "unknown"          # фильтр «ОС не определена» в API

# Источник -> ранг точности (больше — точнее).
SOURCE_RANK = {"nmap": 1, "banner": 2, "ssh": 3}

# (ключ, подпись, ID из os-release, регэксп по названию). Порядок важен:
# производные дистрибутивы раньше базовых (Astra раньше Debian).
_FAMILIES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("astra", "Astra Linux", ("astra",), r"astra"),
    ("redos", "РЕД ОС", ("redos",), r"\bred\s*os\b|\bредос\b|\bред\s+ос\b|red-soft"),
    ("alt", "Альт", ("altlinux", "alt"), r"\balt\s*linux\b|\baltlinux\b|\bальт\b"),
    ("rosa", "РОСА", ("rosa",), r"\brosa\b|\bроса\b"),
    ("msvsphere", "МСВСфера", ("msvsphere",), r"msvsphere|мсвсфера"),
    ("osnova", "ОС Основа", ("osnova",), r"\bosnova\b|ос\s+основа"),
    ("ubuntu", "Ubuntu", ("ubuntu",), r"ubuntu"),
    ("debian", "Debian", ("debian",), r"debian|\+deb\d"),
    ("centos", "CentOS", ("centos",), r"centos"),
    ("rocky", "Rocky Linux", ("rocky",), r"\brocky\b"),
    ("almalinux", "AlmaLinux", ("almalinux",), r"alma\s*linux"),
    ("oracle", "Oracle Linux", ("ol",), r"oracle\s+linux"),
    ("rhel", "Red Hat Enterprise Linux", ("rhel",), r"red\s*hat|\brhel\b"),
    ("fedora", "Fedora", ("fedora",), r"fedora"),
    ("suse", "SUSE / openSUSE", ("sles", "sled", "opensuse", "opensuse-leap",
                                 "opensuse-tumbleweed"), r"\bsuse\b|opensuse|\bsles\b"),
    ("alpine", "Alpine Linux", ("alpine",), r"alpine"),
    (GENERIC_LINUX, "Linux (дистрибутив не определён)", ("linux",), r"linux"),
    ("windows", "Windows", ("windows",), r"windows|microsoft"),
    ("macos", "macOS / Apple", ("macos",), r"mac\s*os|apple|darwin"),
    ("bsd", "BSD", ("freebsd", "openbsd", "netbsd"), r"bsd"),
    ("network", "Сетевое оборудование", (),
     (r"cisco|\bios\b|routeros|mikrotik|juniper|junos|huawei|\bvrp\b|fortinet|fortios"
      r"|eltex|элтекс|keenetic|zyxel|d-link|tp-link|ubiquiti|edgeos|aruba|arista")),
)
_LABELS = {key: label for key, label, _, _ in _FAMILIES} | {
    "other": "Другая ОС", UNKNOWN: "ОС не определена"}
_BY_ID = {i: key for key, _, ids, _ in _FAMILIES for i in ids}
_REGEX = [(key, re.compile(rx, re.IGNORECASE)) for key, _, _, rx in _FAMILIES]

_DISTROS = frozenset(k for k, *_ in _FAMILIES[:[k for k, *_ in _FAMILIES].index(GENERIC_LINUX)])

# Порядок групп в интерфейсе и отчётах: отечественные ОС первыми.
FAMILY_ORDER = tuple(key for key, *_ in _FAMILIES) + ("other", UNKNOWN)


def family_label(family: str | None) -> str:
    return _LABELS.get(family or UNKNOWN, family or _LABELS[UNKNOWN])


def classify(name: str | None, os_id: str | None = None,
             id_like: str | None = None) -> str | None:
    """Семейство по названию ОС и (если есть) ID / ID_LIKE из os-release.

    Возвращает ключ семейства, ``"other"`` для непустого, но неизвестного
    названия, ``None`` — если определять не из чего.
    """
    if os_id and os_id.strip().lower() in _BY_ID:
        return _BY_ID[os_id.strip().lower()]
    by_name = next((key for key, rx in _REGEX if name and rx.search(name)), None)
    if by_name not in (None, GENERIC_LINUX):
        return by_name
    for like in (id_like or "").lower().split():
        if like in _BY_ID:
            return _BY_ID[like]
    if by_name or os_id:   # os-release есть, но дистрибутив неизвестен — это Linux
        return GENERIC_LINUX
    return "other" if name and name.strip() else None


def is_distro(family: str | None) -> bool:
    """Семейство указывает конкретный дистрибутив Linux (а не просто «Linux»)."""
    return family in _DISTROS
