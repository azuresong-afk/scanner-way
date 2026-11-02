"""Бюллетени по требованию: выпуски ОС, которые реально встретились в прогоне.

Раньше сверка с бюллетенями работала, только если оператор заранее перечислил
выпуски в ADVISORY_RELEASES и вручную запустил загрузку; иначе каждый хост
получал «нет данных вендора», и проверка бэкпортов фактически не выполнялась.

Теперь модуль auth_inventory после сбора инвентаря знает точный выпуск каждого
хоста (os-release) и просит загрузить недостающие:
  * файл из ADVISORY_DIR (закрытый контур, Astra Linux, РЕД ОС) — всегда;
  * из интернета (адрес вендора) — только с согласия оператора: включено
    автообновление «Бюллетени дистрибутивов» в «Справочниках» или
    ADVISORY_ON_DEMAND=1. Сканер не выходит в интернет без ведома оператора.

Загруженный выпуск остаётся в distro_advisory, и плановое обновление дальше
обновляет его само (см. ``wanted_releases``).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from scanner.feeds.advisories import FAMILIES
from scanner.feeds.advisories.store import AdvisoryStore
from scanner.feeds.advisories.sync import (
    EXTENSIONS,
    ReleaseResult,
    _download,
    local_file,
    sync_releases,
)

NO_CONSENT = ("загрузка из интернета не разрешена: включите автообновление "
              "«Бюллетени дистрибутивов» в «Справочниках» (или ADVISORY_ON_DEMAND=1) "
              "либо положите файл в каталог бюллетеней")


def local_releases(directory: Path | None) -> set[tuple[str, str]]:
    """Выпуски, для которых в каталоге оператора лежит файл ``<семейство>-<выпуск>.<расш>``."""
    out: set[tuple[str, str]] = set()
    if directory is None or not directory.is_dir():
        return out
    exts = sorted((e for e in EXTENSIONS if e), key=len, reverse=True)
    for p in directory.iterdir():
        if not p.is_file():
            continue
        stem = p.name
        for ext in exts:
            if stem.endswith(ext):
                stem = stem[: -len(ext)]
                break
        family, sep, release = stem.partition("-")
        if sep and release and family in FAMILIES:
            out.add((family, release))
    return out


def wanted_releases(configured: Iterable[tuple[str, str]], store: AdvisoryStore,
                    directory: Path | None) -> list[tuple[str, str]]:
    """Что обновлять по расписанию: ADVISORY_RELEASES + уже загруженные выпуски
    (в том числе подгруженные по требованию) + файлы в каталоге оператора."""
    out = list(dict.fromkeys(configured))
    extra = set(store.releases()) | local_releases(directory)
    out += sorted(t for t in extra if t not in out and t[0] in FAMILIES)
    return out


@dataclass(slots=True)
class AdvisoryFetcher:
    """Загружает бюллетени недостающих выпусков; вызывается модулем прогона."""
    store: AdvisoryStore
    directory: Path | None = None
    urls: dict[str, str] = field(default_factory=dict)
    # Согласие на выход в интернет проверяется в момент прогона: оператор мог
    # включить/выключить автообновление после старта API.
    allow_network: Callable[[], bool] = lambda: False
    fetch: Callable[[str, Path], None] = _download

    def __call__(self, targets: Iterable[tuple[str, str]]) -> list[ReleaseResult]:
        targets = [t for t in dict.fromkeys(targets) if t[0] in FAMILIES]
        if not targets:
            return []
        try:
            network = bool(self.allow_network())
        except Exception:  # noqa: BLE001 — нет ответа о согласии = согласия нет
            network = False
        chosen = [t for t in targets
                  if network or local_file(self.directory, *t) is not None]
        skipped = [ReleaseResult(f, r, error=NO_CONSENT) for f, r in targets
                   if (f, r) not in chosen]
        if not chosen:
            return skipped
        results, _ = sync_releases(self.store, chosen, directory=self.directory,
                                   urls=self.urls, fetch=self.fetch)
        return [*results, *skipped]
