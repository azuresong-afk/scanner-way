"""Потоковый разбор OVAL (патч-определения вендоров) -> записи бюллетеня.

Формат один у Ubuntu (USN OVAL), Red Hat (OVAL v2), ALT, РЕД ОС и Astra Linux:
определение (definition) несёт CVE (``reference source="CVE"`` /
``advisory/cve``) и критерии — ссылки на тесты ``rpminfo_test`` /
``dpkginfo_test``; тест связывает объект (имя пакета, прямо или через
``constant_variable``) с состоянием «версия less than X». X — первая
исправленная версия пакета.

Логика AND/OR критериев намеренно не вычисляется: берутся все тесты
«пакет < версия» определения. Прочие тесты (подпись ключом вендора, версия
release-пакета, архитектура, ядро через uname) пропускаются — у них нет
состояния «evr less than».

Файлы большие (RHEL — сотни МБ после распаковки), поэтому разбор потоковый:
элементы верхнего уровня секций очищаются сразу после чтения.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from typing import IO

from scanner.feeds.advisories.base import FIXED, Advisory, is_cve

_TESTS = ("rpminfo_test", "dpkginfo_test")
_OBJECTS = ("rpminfo_object", "dpkginfo_object")
_STATES = ("rpminfo_state", "dpkginfo_state")
# Ссылки на бюллетень, кроме самих CVE: id бюллетеня для evidence.
_ADVISORY_SOURCES = ("RHSA", "USN", "DSA", "DLA", "ALAS", "ELSA", "ALSA", "RLSA",
                     "ALT", "ALTPU", "BDU", "ASTRA", "REDOS", "ROSA", "OVAL")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in el if _local(c.tag) == name), None)


def _definition(el: ET.Element) -> tuple[str | None, list[str], list[str]]:
    """(id бюллетеня, CVE, test_ref) определения."""
    cves: list[str] = []
    adv: str | None = None
    tests: list[str] = []
    for sub in el.iter():
        tag = _local(sub.tag)
        if tag == "reference":
            src = (sub.get("source") or "").strip().upper()
            ref = (sub.get("ref_id") or "").strip()
            if src == "CVE" and is_cve(ref):
                cves.append(ref)
            elif ref and adv is None and src.split("-")[0] in _ADVISORY_SOURCES:
                adv = ref
        elif tag == "cve":
            text = (sub.text or "").strip()
            if is_cve(text):
                cves.append(text)
        elif tag == "criterion":
            if sub.get("test_ref"):
                tests.append(sub.get("test_ref"))  # type: ignore[arg-type]
        elif tag == "title" and adv is None:
            # «USN-6200-1 -- OpenSSL vulnerabilities», «RHSA-2024:0310: openssl …»
            head = (sub.text or "").strip().split(" ", 1)[0].rstrip(":")
            if head.split("-")[0].upper() in _ADVISORY_SOURCES and any(
                    ch.isdigit() for ch in head):
                adv = head
    return adv, list(dict.fromkeys(cves)), tests


def parse_oval(stream: IO[bytes], family: str, releases: Iterable[str]) -> Iterator[Advisory]:
    """OVAL одного выпуска -> записи «fixed». releases — ровно один выпуск
    (файл OVAL у вендоров свой на каждый выпуск)."""
    rels = list(releases)
    if len(rels) != 1:
        raise ValueError("файл OVAL описывает один выпуск дистрибутива")
    release = rels[0]

    definitions: list[tuple[str | None, list[str], list[str]]] = []
    tests: dict[str, tuple[str | None, str | None]] = {}       # id -> (object, state)
    objects: dict[str, tuple[str | None, str | None]] = {}     # id -> (name, var_ref)
    states: dict[str, str] = {}                                # id -> evr (less than)
    variables: dict[str, list[str]] = {}

    for _event, el in ET.iterparse(stream, events=("end",)):
        tag = _local(el.tag)
        if tag == "definition":
            adv, cves, refs = _definition(el)
            if cves and refs:
                definitions.append((adv, cves, refs))
        elif tag in _TESTS:
            obj, st = _child(el, "object"), _child(el, "state")
            tests[el.get("id", "")] = (
                obj.get("object_ref") if obj is not None else None,
                st.get("state_ref") if st is not None else None)
        elif tag in _OBJECTS:
            name = _child(el, "name")
            if name is not None:
                objects[el.get("id", "")] = ((name.text or "").strip() or None,
                                             name.get("var_ref"))
        elif tag in _STATES:
            evr = _child(el, "evr")
            if evr is not None and (evr.get("operation") or "").lower() == "less than" \
                    and (evr.text or "").strip():
                states[el.get("id", "")] = evr.text.strip()  # type: ignore[union-attr]
        elif tag == "constant_variable":
            variables[el.get("id", "")] = [(v.text or "").strip() for v in el
                                           if _local(v.tag) == "value" and v.text]
        else:
            continue
        el.clear()

    seen: set[tuple[str, str, str]] = set()
    for adv, cves, refs in definitions:
        for ref in refs:
            obj_id, state_id = tests.get(ref, (None, None))
            fixed = states.get(state_id or "")
            if not fixed or obj_id is None:
                continue
            obj_name, var = objects.get(obj_id, (None, None))
            names = [obj_name] if obj_name else variables.get(var or "", [])
            for pkg in names:
                for cve in cves:
                    key = (pkg, cve, fixed)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Advisory(family, release, pkg, cve, FIXED, fixed, adv)
