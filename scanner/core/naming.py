"""Имя прогона по выбранным опциям: что проверяем и где.

Вместо безликого «Прогон №7» оператор видит, например,
«Обнаружение + Nuclei · 10.0.0.0/24» или
«Nuclei + учётная запись + конфигурации · 10.0.1.15, 10.0.1.16 и ещё 3».
Имя считается при постановке и хранится в scan_runs.name; оператор может
задать своё — тогда автоматическое не используется.
"""
from __future__ import annotations

from collections.abc import Iterable

# Подписи модулей в имени, в порядке исполнения (MODULE_ORDER).
_PARTS: tuple[tuple[str, str], ...] = (
    ("discovery", "обнаружение"),
    ("vuln", "Nuclei"),
    ("auth_inventory", "учётная запись"),
    ("config_audit", "конфигурации"),
    ("cred_audit", "пароли"),
)
# Единственный модуль — подпись полнее, иначе «Учётная запись · …» непонятно.
_ALONE = {"auth_inventory": "по учётной записи", "config_audit": "аудит конфигураций",
          "cred_audit": "аудит паролей", "discovery": "инвентаризация"}

MAX_NAME_LENGTH = 200
_SHOWN_TARGETS = 2


def _capitalize(s: str) -> str:
    return s[:1].upper() + s[1:]


def modules_label(modules: Iterable[str]) -> str:
    names = list(dict.fromkeys(modules))
    if len(names) == 1 and names[0] in _ALONE:
        return _capitalize(_ALONE[names[0]])
    known = dict(_PARTS)
    parts = [label for m, label in _PARTS if m in names]
    parts += [m for m in names if m not in known]
    return _capitalize(" + ".join(parts)) if parts else "Прогон"


def targets_label(targets: Iterable[str]) -> str:
    items = [t.strip() for t in targets if t and t.strip()]
    items = list(dict.fromkeys(items))
    if not items:
        return ""
    shown = ", ".join(items[:_SHOWN_TARGETS])
    rest = len(items) - _SHOWN_TARGETS
    return f"{shown} и ещё {rest}" if rest > 0 else shown


def run_title(modules: Iterable[str], targets: Iterable[str] = ()) -> str:
    """Автоматическое имя прогона/расписания по модулям и целям."""
    title = modules_label(modules)
    where = targets_label(targets)
    if where:
        title = f"{title} · {where}"
    return clean_name(title) or "Прогон"


def clean_name(name: str | None) -> str | None:
    """Имя, заданное оператором: без лишних пробелов, не длиннее лимита; пустое — None."""
    if name is None:
        return None
    name = " ".join(name.split())
    if not name:
        return None
    return name if len(name) <= MAX_NAME_LENGTH else name[:MAX_NAME_LENGTH - 1] + "…"
