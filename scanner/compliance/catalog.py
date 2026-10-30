"""Профили соответствия как данные: загрузка и проверка YAML (R5).

Файлы — в `scanner/compliance/profiles/`: `checks.yaml` (каталог технических
проверок) и по файлу на профиль (fstec-117, fstec-21, fstec-239,
cis-controls-v8, cis-benchmark). Профиль ссылается на проверки по id; ссылка на
несуществующую проверку, повтор id меры или уровня вне списка — ошибка загрузки
(ловится тестом, а не в отчёте заказчика).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROFILES_DIR = Path(__file__).with_name("profiles")
PLATFORMS = ("linux", "windows", "any")
WIN_OPS = ("eq", "ne", "ge", "le")
SEVERITIES = ("low", "medium", "high", "critical")
# Профили по порядку показа.
PROFILE_ORDER = ("fstec-117", "fstec-21", "fstec-239", "cis-controls-v8", "cis-benchmark")


class CatalogError(ValueError):
    """Ошибка в данных профиля или каталога проверок."""


@dataclass(frozen=True, slots=True)
class WinCondition:
    key: str
    op: str
    value: int
    missing: int | None          # значение по умолчанию; None — «нет данных»
    when: WinCondition | None = None


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    title: str
    platform: str
    remediation: str
    doc: str | None = None
    openscap: tuple[str, ...] = ()
    lynis: tuple[str, ...] = ()
    password_policy: tuple[str, ...] = ()
    windows: tuple[WinCondition, ...] = ()
    vulns: dict[str, Any] | None = None
    services: dict[str, Any] | None = None
    cred_audit: bool = False


@dataclass(frozen=True, slots=True)
class Control:
    id: str
    title: str
    group: str
    group_title: str
    levels: tuple[str, ...]
    checks: tuple[str, ...] = ()

    @property
    def manual(self) -> bool:
        """Организационная мера: автоматических проверок нет."""
        return not self.checks


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    title: str
    short: str
    document: str
    url: str
    level_label: str
    levels: tuple[str, ...]
    default_level: str | None
    controls: tuple[Control, ...] = ()
    dynamic: str | None = None
    groups: tuple[tuple[str, str], ...] = field(default=())

    def control(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.id == control_id), None)

    def base_set(self, level: str | None) -> list[Control]:
        """Базовый набор мер для уровня (класса/УЗ/категории/IG); без уровня — все."""
        if level is None or not self.levels:
            return list(self.controls)
        return [c for c in self.controls if level in c.levels]

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "short": self.short,
                "document": self.document, "url": self.url,
                "level_label": self.level_label, "levels": list(self.levels),
                "default_level": self.default_level, "dynamic": self.dynamic,
                "groups": [{"code": c, "title": t} for c, t in self.groups],
                "controls": [{"id": c.id, "title": c.title, "group": c.group,
                              "levels": list(c.levels), "checks": list(c.checks),
                              "manual": c.manual} for c in self.controls]}


@dataclass(frozen=True, slots=True)
class Catalog:
    checks: dict[str, Check]
    profiles: dict[str, Profile]

    def profile(self, profile_id: str) -> Profile:
        try:
            return self.profiles[profile_id]
        except KeyError:
            raise KeyError(f"неизвестный профиль соответствия: {profile_id}") from None


def _tuple(v: Any, what: str) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise CatalogError(f"{what}: ожидается список строк")
    return tuple(v)


def _win(raw: Any, where: str) -> WinCondition:
    if not isinstance(raw, dict) or not raw.get("key"):
        raise CatalogError(f"{where}: условие windows без key")
    op = raw.get("op", "eq")
    if op not in WIN_OPS:
        raise CatalogError(f"{where}: недопустимая операция {op!r}")
    missing = raw.get("missing", "na")
    when = _win(raw["when"], where) if raw.get("when") else None
    return WinCondition(key=str(raw["key"]), op=op, value=int(raw["value"]),
                        missing=None if missing == "na" else int(missing), when=when)


def _check(raw: dict) -> Check:
    cid = raw.get("id")
    if not cid or not raw.get("title") or not raw.get("remediation"):
        raise CatalogError(f"проверка {cid!r}: нужны id, title и remediation")
    platform = raw.get("platform", "any")
    if platform not in PLATFORMS:
        raise CatalogError(f"проверка {cid}: platform {platform!r}")
    vulns = raw.get("vulns")
    if vulns is not None and vulns.get("min_severity") not in SEVERITIES:
        raise CatalogError(f"проверка {cid}: vulns.min_severity")
    c = Check(id=cid, title=raw["title"], platform=platform,
              remediation=" ".join(str(raw["remediation"]).split()), doc=raw.get("doc"),
              openscap=_tuple(raw.get("openscap"), f"{cid}.openscap"),
              lynis=_tuple(raw.get("lynis"), f"{cid}.lynis"),
              password_policy=_tuple(raw.get("password_policy"), f"{cid}.password_policy"),
              windows=tuple(_win(w, cid) for w in raw.get("windows") or ()),
              vulns=vulns, services=raw.get("services"),
              cred_audit=bool(raw.get("cred_audit")))
    if not (c.openscap or c.lynis or c.password_policy or c.windows or c.vulns
            or c.services or c.cred_audit):
        raise CatalogError(f"проверка {cid}: нет ни одного источника")
    return c


def _profile(raw: dict, checks: dict[str, Check]) -> Profile:
    pid = raw.get("id")
    for key in ("id", "title", "short", "document", "url", "level_label"):
        if not raw.get(key):
            raise CatalogError(f"профиль {pid!r}: нет поля {key}")
    levels = tuple(str(x) for x in raw.get("levels") or ())
    default = raw.get("default_level")
    if default is not None and str(default) not in levels:
        raise CatalogError(f"профиль {pid}: default_level вне levels")
    controls: list[Control] = []
    groups: list[tuple[str, str]] = []
    seen: set[str] = set()
    for g in raw.get("groups") or ():
        code, gtitle = str(g["code"]), str(g["title"])
        groups.append((code, gtitle))
        for c in g.get("controls") or ():
            cid = str(c.get("id") or "")
            if not cid or not c.get("title"):
                raise CatalogError(f"профиль {pid}, группа {code}: мера без id/title")
            if cid in seen:
                raise CatalogError(f"профиль {pid}: мера {cid} повторяется")
            seen.add(cid)
            lv = tuple(str(x) for x in c.get("levels", levels))
            bad = [x for x in lv if x not in levels]
            if bad:
                raise CatalogError(f"профиль {pid}, мера {cid}: уровни {bad} вне {levels}")
            refs = _tuple(c.get("checks"), f"{pid}.{cid}.checks")
            unknown = [r for r in refs if r not in checks]
            if unknown:
                raise CatalogError(f"профиль {pid}, мера {cid}: нет проверок {unknown}")
            controls.append(Control(id=cid, title=" ".join(str(c["title"]).split()),
                                    group=code, group_title=gtitle, levels=lv, checks=refs))
    dynamic = raw.get("dynamic")
    if dynamic not in (None, "openscap_cis"):
        raise CatalogError(f"профиль {pid}: неизвестный dynamic {dynamic!r}")
    if not controls and not dynamic:
        raise CatalogError(f"профиль {pid}: нет мер")
    return Profile(id=pid, title=raw["title"], short=raw["short"],
                   document=" ".join(str(raw["document"]).split()), url=raw["url"],
                   level_label=raw["level_label"], levels=levels,
                   default_level=str(default) if default is not None else None,
                   controls=tuple(controls), dynamic=dynamic, groups=tuple(groups))


def load_catalog(directory: Path | None = None) -> Catalog:
    d = directory or PROFILES_DIR
    raw_checks = yaml.safe_load((d / "checks.yaml").read_text(encoding="utf-8"))
    checks: dict[str, Check] = {}
    for raw in raw_checks.get("checks") or ():
        c = _check(raw)
        if c.id in checks:
            raise CatalogError(f"проверка {c.id} повторяется")
        checks[c.id] = c
    profiles: dict[str, Profile] = {}
    for path in sorted(d.glob("*.yaml")):
        if path.name == "checks.yaml":
            continue
        p = _profile(yaml.safe_load(path.read_text(encoding="utf-8")), checks)
        if p.id in profiles:
            raise CatalogError(f"профиль {p.id} повторяется")
        profiles[p.id] = p
    order = {pid: i for i, pid in enumerate(PROFILE_ORDER)}
    profiles = dict(sorted(profiles.items(), key=lambda kv: (order.get(kv[0], 99), kv[0])))
    return Catalog(checks=checks, profiles=profiles)


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return load_catalog()
