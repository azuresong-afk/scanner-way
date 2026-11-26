"""Исправления вендора, записанные в самой БДУ ФСТЭК («Возможные меры по устранению»).

В записях БДУ Astra Linux вендор указывает точную версию исправленного пакета:

    Для ОС Astra Linux:
    обновить пакет liblivemedia до 2:2024.11.28-1.astra1+ci3 или более высокой
    версии, используя рекомендации производителя:
    https://wiki.astralinux.ru/astra-linux-se17-bulletin-2025-0319SE17

В выгрузке vullist.xlsx таких указаний для Astra — десятки тысяч. Если OVAL
Astra не загружен или в нём нет записи, это второй источник решения вендора
для хоста Astra: «установлена версия не ниже — закрыто», «ниже — уязвим,
обновить до X».

Выпуск указания берётся из заголовка («Astra Linux Special Edition 1.7»,
«Astra Linux 1.6 «Смоленск»») или из ссылки на бюллетень
(``astra-linux-se17-bulletin`` -> 1.7). Указание другого выпуска к хосту не
относится; выпуск не определён — указание относится ко всем выпускам, а решение
(scanner.feeds.advisories.assess.decide) берёт наибольшую исправленную версию
той же ветки, поэтому «закрыто» объявляется консервативно.

Для РЕД ОС БДУ даёт только ссылки на страницы вендора, без версий, — их здесь
не разбираем.
"""
from __future__ import annotations

import re

from scanner.feeds.advisories.base import FIXED, Advisory

# Заголовок блока «Для ОС Astra Linux Special Edition 1.7:» / «Astra Linux 1.6 …:».
_HEAD_RE = re.compile(r"(?:Для\s+(?:ОС\s+)?)?(Astra\s+Linux[^\n:]{0,80}):", re.IGNORECASE)
_FIX_RE = re.compile(r"обновить\s+пакет\s+([A-Za-z0-9][\w.+\-]*)\s+до\s+([0-9][\w.:+~\-]*)",
                     re.IGNORECASE)
_URL_REL_RE = re.compile(r"astra-linux-se(\d)(\d)-bulletin", re.IGNORECASE)
_HEAD_REL_RE = re.compile(r"(\d+\.\d+)")
_URL_RE = re.compile(r"https?://\S+")


def _release(head: str, url: str | None) -> str | None:
    if re.search(r"Эльбрус|Elbrus", head, re.IGNORECASE):
        m = _HEAD_REL_RE.search(head)
        return f"elbrus-{m.group(1)}" if m else "elbrus"
    m = _HEAD_REL_RE.search(head)
    if m:
        return m.group(1)
    if url:
        u = _URL_REL_RE.search(url)
        if u:
            return f"{u.group(1)}.{u.group(2)}"
    return None


def astra_fixes(remediation: str | None) -> list[tuple[str | None, str, str, str | None]]:
    """Текст «Возможные меры» -> [(выпуск | None, пакет, версия, ссылка)]."""
    text = remediation or ""
    out: list[tuple[str | None, str, str, str | None]] = []
    heads = list(_HEAD_RE.finditer(text))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        # блок заголовка — до следующего «Для …:» (другое ПО / ОС)
        nxt = re.search(r"\n\s*Для\s+[^\n]{1,80}:", text[h.end():end])
        block = text[h.end(): h.end() + nxt.start()] if nxt else text[h.end():end]
        url_m = _URL_RE.search(block)
        url = url_m.group(0).rstrip(".,;)") if url_m else None
        for fx in _FIX_RE.finditer(block):
            version = fx.group(2).rstrip(".,;")
            out.append((_release(h.group(1), url), fx.group(1).lower(), version, url))
    return list(dict.fromkeys(out))


def astra_rows(remediation: str | None, vuln_id: str, host_release: str) -> list[Advisory]:
    """Указания Astra из записи БДУ, относящиеся к выпуску хоста, как записи
    бюллетеня (поле cve — идентификатор находки, чтобы decide() их нашёл)."""
    rows = []
    for rel, pkg, ver, url in astra_fixes(remediation):
        if rel is not None and not _same(rel, host_release):
            continue
        rows.append(Advisory("astra", host_release, pkg, vuln_id, FIXED, ver,
                             _bulletin_id(url)))
    return rows


def _same(a: str, b: str) -> bool:
    pa, pb = a.split("."), b.split(".")
    n = min(len(pa), len(pb))
    return pa[:n] == pb[:n]


def _bulletin_id(url: str | None) -> str | None:
    if not url:
        return "БДУ ФСТЭК"
    m = re.search(r"bulletin-[\w-]+", url)
    return m.group(0) if m else url[:120]
