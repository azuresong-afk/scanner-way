"""Ядро Linux: какое ядро РАБОТАЕТ на хосте и какие его уязвимости закрыты.

Уязвимости ядра нельзя проверять «по установленным пакетам» так же, как
openssl: на хосте обычно стоят несколько ядер (старые остаются для отката), а
работает одно — то, с которого хост загружен (``uname -r``). Обновлённое, но
не загруженное ядро уязвимость не закрывает, пока хост не перезагружен.
Поэтому:

* работающее ядро определяется по ``uname -r`` и сопоставляется с пакетом
  образа ядра (``linux-image-6.1.0-18-amd64``, ``kernel-core``, ``kernel-lt``,
  ``kernel-image-std-def``, ``linux-lts``) — сравнивается ЕГО версия;
* бюллетени вендора — те же, что для остальных пакетов (``feeds.advisories``):
  трекер Debian ведёт ядро под исходным пакетом ``linux``, OVAL Red Hat/ALT/
  РЕД ОС/Astra — под бинарными пакетами ядра, Ubuntu (USN OVAL) — проверкой
  «работает ядро по шаблону uname + ABI ядра меньше X» (``UNAME_PREFIX``);
* если установлено более новое ядро, в котором CVE уже исправлена, находка
  остаётся (работает уязвимое), а в рекомендации — «перезагрузите хост»;
* livepatch: CVE, закрытые патчем «на лету», не считаются открытыми —
  Canonical Livepatch (``canonical-livepatch status``, список исправленных CVE)
  и kpatch Red Hat (пакет ``kpatch-patch-<версия ядра>`` по тем же бюллетеням).
  Модули в ``/sys/kernel/livepatch`` без списка CVE находку не закрывают —
  только упоминаются в сводке.

Сопоставления ядра «по версии апстрима» с NVD/БДУ нет намеренно: дистрибутивы
переносят тысячи исправлений в свои сборки, версия ``6.1.0-18`` ничего не
говорит о закрытых CVE, и по БДУ это десятки тысяч записей «Linux».
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from scanner.core.models import InstalledPackage
from scanner.feeds import vercmp

# Пакет-«шаблон uname» в distro_advisory: записи Ubuntu вида
# «работает ядро по шаблону P и его ABI меньше X» (oval.parse_oval_releases).
UNAME_PREFIX = "uname:"
MAX_UNAME_PATTERN = 300

# Исходные пакеты, под которыми вендоры ведут ядро (кроме имён самих пакетов).
SOURCE_ALIASES = {"dpkg": ("linux",), "rpm": ("kernel",), "apk": ()}

_DPKG_IMAGE_RE = re.compile(r"linux-image-(?:unsigned-)?(?P<rel>\d[\w.+~-]*)")
_RPM_IMAGE_RE = re.compile(
    r"kernel(?:-(?:core|lt|ml|uek|rt|default|pae|lt-core|ml-core|uek-core|rt-core|"
    r"pae-core))?|kernel-image-(?P<flavor>[\w.-]+)")
_APK_IMAGE_RE = re.compile(r"linux-(?P<flavor>lts|virt|edge|stable|rpi\d*)")
_ABI_RE = re.compile(r"\d+(?:\.\d+)*-\d+")
_EPOCH_RE = re.compile(r"^\d+:")
_CVE_RE = re.compile(r"cve-\d{4}-\d{4,}", re.IGNORECASE)
_KPATCH_PREFIX = "kpatch-patch-"


def is_image(p: InstalledPackage) -> bool:
    """Пакет — образ ядра (не заголовки, не модули, не мета-пакет)."""
    if p.manager == "dpkg":
        return bool(_DPKG_IMAGE_RE.fullmatch(p.name))
    if p.manager == "rpm":
        return bool(_RPM_IMAGE_RE.fullmatch(p.name))
    if p.manager == "apk":
        return bool(_APK_IMAGE_RE.fullmatch(p.name))
    return False


def image_release(p: InstalledPackage) -> str | None:
    """Строка ``uname -r``, которую даст ядро из этого пакета (если её можно вывести)."""
    if p.manager == "dpkg":
        m = _DPKG_IMAGE_RE.fullmatch(p.name)
        return m["rel"] if m else None
    if p.manager == "rpm":
        m = _RPM_IMAGE_RE.fullmatch(p.name)
        if not m:
            return None
        ver, _, rel = _EPOCH_RE.sub("", p.version).partition("-")
        if m["flavor"]:                              # ALT: 6.1.79-std-def-alt1
            return f"{ver}-{m['flavor']}-{rel}"
        return f"{ver}-{rel}" + (f".{p.arch}" if p.arch else "")
    if p.manager == "apk":
        m = _APK_IMAGE_RE.fullmatch(p.name)
        ver, _, rel = p.version.partition("-r")
        return f"{ver}-{rel}-{m['flavor']}" if m and rel else None
    return None


def _runs(p: InstalledPackage, release: str) -> bool:
    got = image_release(p)
    if got is None:
        return False
    if got == release:
        return True
    # rpm: архитектура не пришла в выводе / uname без архитектуры (РЕД ОС, CentOS 6)
    return p.manager == "rpm" and (release.startswith(got + ".")
                                   or got.startswith(release + "."))


def flavor(release: str | None) -> str:
    """Вариант сборки ядра: ``5.15.0-89-generic`` -> ``-generic``."""
    m = _ABI_RE.match(release or "")
    return (release or "")[m.end():] if m else ""


def abi(release: str | None) -> str | None:
    """ABI ядра Ubuntu из ``uname -r``: ``5.15.0-89-generic`` -> ``5.15.0-89``."""
    m = _ABI_RE.match(release or "")
    return m.group(0) if m else None


def uname_matches(pattern: str, release: str) -> bool:
    """Шаблон вендора (регулярное выражение OVAL uname_state) подходит к ``uname -r``."""
    if not pattern or len(pattern) > MAX_UNAME_PATTERN:
        return False
    try:
        return re.fullmatch(pattern, release) is not None
    except re.error:
        return False


@dataclass(slots=True)
class KernelState:
    """Работающее ядро хоста и установленные образы ядра."""
    release: str | None                               # uname -r
    manager: str | None = None
    running: list[InstalledPackage] = field(default_factory=list)
    images: list[InstalledPackage] = field(default_factory=list)
    pending: InstalledPackage | None = None           # более новое ядро того же варианта
    kpatch: list[InstalledPackage] = field(default_factory=list)

    @property
    def package(self) -> InstalledPackage | None:
        return self.running[0] if self.running else None

    @property
    def pending_release(self) -> str | None:
        return image_release(self.pending) if self.pending else None


def kernel_state(release: str | None, packages: Sequence[InstalledPackage]) -> KernelState:
    images = [p for p in packages if is_image(p)]
    managers = {p.manager for p in images}
    st = KernelState(release=release, images=images,
                     manager=next(iter(managers)) if len(managers) == 1 else None)
    if not release:
        return st
    st.running = [p for p in images if _runs(p, release)]
    if st.running:
        st.manager = st.running[0].manager
    run = st.package
    if run is not None:
        same = [p for p in images if p.manager == run.manager and p not in st.running
                and (run.manager != "dpkg" or flavor(image_release(p)) == flavor(release))
                and (run.manager == "dpkg" or p.name == run.name)]
        newer = [p for p in same if vercmp.compare(run.manager, p.version, run.version) > 0]
        for p in newer:
            if st.pending is None or vercmp.compare(p.manager, p.version,
                                                     st.pending.version) > 0:
                st.pending = p
        # kpatch Red Hat: kpatch-patch-5_14_0-362_8_1 — для ядра 5.14.0-362.8.1.el9_3
        ver = _EPOCH_RE.sub("", run.version)
        tag = re.sub(r"\.el\d.*$", "", ver).replace(".", "_")
        st.kpatch = [p for p in packages if p.name == _KPATCH_PREFIX + tag]
    return st


def is_kpatch(name: str) -> bool:
    return name.startswith(_KPATCH_PREFIX)


# ---------- livepatch ----------

def parse_livepatch_modules(lines: Iterable[str]) -> list[str]:
    """Строки «имя enabled» из /sys/kernel/livepatch -> включённые модули."""
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "1" and re.fullmatch(r"[\w.-]{1,128}", parts[0]):
            out.append(parts[0])
    return out


def parse_canonical_livepatch(text: str) -> set[str]:
    """CVE, исправленные Canonical Livepatch, из ``canonical-livepatch status
    --format json``. Учитываются только записи с ``Patched: true``; формат со
    списком строкой — только строки без признаков «не применено»."""
    text = text.strip()
    if not text:
        return set()
    try:
        doc = json.loads(text)
    except ValueError:
        return set()
    out: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            low = {str(k).lower(): v for k, v in node.items()}
            name = low.get("name")
            if isinstance(name, str) and _CVE_RE.fullmatch(name.strip()) \
                    and low.get("patched") is True:
                out.add(name.strip().upper())
            fixes = low.get("fixes")
            if isinstance(fixes, str):
                for line in fixes.splitlines():
                    if re.search(r"unpatched|not applied|false", line, re.IGNORECASE):
                        continue
                    out.update(c.upper() for c in _CVE_RE.findall(line))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return out
