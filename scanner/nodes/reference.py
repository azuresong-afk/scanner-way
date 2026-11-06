"""Справочники центра для узлов: только чтение, белый список методов.

Узел не хранит БДУ ФСТЭК/NVD/бюллетени: модули на узле обращаются к ним через
центр (scanner.nodes.remote), а центр исполняет здесь только перечисленные
методы чтения над своими справочниками. Аргументы — строки (или список строк);
ответ — JSON кодека (scanner.nodes.codec).
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.engine import Engine

from scanner.nodes.codec import to_wire

# хранилище -> метод -> типы аргументов («s» — строка, «l» — список строк)
METHODS: dict[str, dict[str, str]] = {
    "reference": {"get_nvd": "s", "get_bdu": "s", "bdu_by_cve": "s", "cpe_matches": "s",
                  "bdu_by_software": "s", "bdu_software_names": ""},
    "advisory": {"releases": "", "for_packages": "ssl", "with_prefix": "sss"},
    "msrc": {"count": "", "products": "", "fixes_for": "s"},
}
MAX_ARG = 1000          # длина строки
MAX_LIST = 20000        # имён пакетов в одном запросе


class ReferenceError(ValueError):
    pass


def _check_args(sig: str, args: list[Any]) -> list[Any]:
    if not isinstance(args, list) or len(args) != len(sig):
        raise ReferenceError("неверное число аргументов")
    out: list[Any] = []
    for kind, a in zip(sig, args, strict=True):
        if kind == "s":
            if not isinstance(a, str) or len(a) > MAX_ARG:
                raise ReferenceError("аргумент должен быть строкой")
            out.append(a)
        else:
            if (not isinstance(a, list) or len(a) > MAX_LIST
                    or not all(isinstance(x, str) and len(x) <= MAX_ARG for x in a)):
                raise ReferenceError("аргумент должен быть списком строк")
            out.append(a)
    return out


class ReferenceService:
    """Диспетчер запросов узлов к справочникам над engine центра."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self._stores: dict[str, Any] = {}

    def _store(self, name: str) -> Any:
        if name not in self._stores:
            if name == "reference":
                from scanner.feeds.store import SqlReferenceStore
                self._stores[name] = SqlReferenceStore(self.engine)
            elif name == "advisory":
                from scanner.feeds.advisories.store import SqlAdvisoryStore
                self._stores[name] = SqlAdvisoryStore(self.engine)
            elif name == "msrc":
                from scanner.feeds.msrc import MsrcStore
                self._stores[name] = MsrcStore(self.engine)
            else:
                raise ReferenceError(f"неизвестный справочник: {name}")
        return self._stores[name]

    def call(self, store: str, method: str, args: list[Any]) -> Any:
        sig = METHODS.get(store, {}).get(method)
        if sig is None:
            raise ReferenceError(f"метод {store}.{method} недоступен узлам")
        clean = _check_args(sig, args)
        if store == "advisory" and method == "for_packages":
            clean[2] = set(clean[2])
        fn: Callable[..., Any] = getattr(self._store(store), method)
        return to_wire(fn(*clean))
