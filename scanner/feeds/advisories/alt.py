"""ALT (Альт): OVAL errata из rdb.altlinux.org, архив на ветку (p10, p11).

Выпуск — ветка репозитория: VERSION_ID ``10.1`` -> ``p10``.
"""
from __future__ import annotations

from scanner.feeds.advisories.base import FamilySpec, major
from scanner.feeds.advisories.oval import parse_oval


def release_of(version_id: str | None, codename: str | None) -> str | None:
    v = (version_id or "").strip().lower()
    if v.startswith(("p", "c")) and v[1:2].isdigit():
        return v                             # уже ветка: p10, c10f2
    m = major(v)
    return f"p{m}" if m else None


SPEC = FamilySpec(
    family="alt", label="Альт", manager="rpm", parser=parse_oval,
    default_url="https://rdb.altlinux.org/api/errata/export/oval/{release}",
    host_families=("alt",), release_of=release_of, note="OVAL errata ALT")
