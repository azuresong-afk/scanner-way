"""Ложные уязвимости на РЕД ОС 8 (пример с лабы: ImageMagick 7.1.2.25-4.red80).

Бюллетени РЕД ОС 8 загружены, но по версии апстрима ImageMagick находилось
14 CVE: записи БДУ с испорченными диапазонами («от 7.0.8 до 68», «до 14.8.2»,
«от 7.0.0») и записи, где из дистрибутивов назван только РЕД ОС 7.3.
Записи БДУ ниже — дословные выдержки «Версия ПО» из выгрузки vullist.xlsx.
"""
from __future__ import annotations

from scanner.core.audit import AuditSink
from scanner.feeds.advisories import bduscope
from scanner.feeds.advisories.base import FIXED, Advisory
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.bdu_fstec import BduRecord, parse_bdu_versions
from scanner.feeds.matcher import BACKPORT_CAVEAT, VulnMatcher
from scanner.modules.auth_inventory import AuthInventoryModule
from tests.test_auth_inventory import FakeShell, cred, ctx_for, reference_store

REDOS_8 = 'NAME="RED OS"\nVERSION="8.0"\nID="redos"\nVERSION_ID="8.0"\n' \
          'PRETTY_NAME="RED OS MUROM (8.0)"'
HIGH = "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 7,5)"


def redos_host(*rows: str) -> str:
    body = "\n".join(rows)
    return f"@@os-release\n{REDOS_8}\n@@rpm\n{body}\n@@end\n"


IMAGEMAGICK = "ImageMagick\t7.1.2.25-4.red80\tx86_64\tImageMagick-7.1.2.25-4.red80.src.rpm"
LIBTIFF = "libtiff\t4.6.0-3.red80\tx86_64\tlibtiff-4.6.0-3.red80.src.rpm"


def bdu(bdu_id: str, cve: str, versions: str) -> BduRecord:
    return BduRecord(bdu_id=bdu_id, title=f"Уязвимость {cve}", versions=versions,
                     cve_ids=[cve], severity_text=HIGH)


RECORDS = [
    # испорченные диапазоны ImageMagick, без РЕД ОС
    bdu("BDU:2017-00621", "CVE-2015-8894", "от 7.0.0 (ImageMagick)"),
    bdu("BDU:2017-01289", "CVE-2017-8765", "от 7.0.5 до 7.5 (ImageMagick)"),
    bdu("BDU:2021-01009", "CVE-2020-27752",
        "15.1 (OpenSUSE Leap), от 7.0.8 до 68 (ImageMagick), 1.7 (Astra Linux Special "
        "Edition)"),
    bdu("BDU:2025-12589", "CVE-2025-55212",
        "7.3 (РЕД ОС), 12.4 (РОСА ХРОМ), - (АЛЬТ СП 10), от 6.9.13-28 (ImageMagick), "
        "от 7.0.0-0 до 7.1.2-2 (ImageMagick)"),
    # РЕД ОС назван, но только 7.3
    bdu("BDU:2025-12702", "CVE-2025-57807",
        "22.04 LTS (Ubuntu), 12 (Debian GNU/Linux), 7.3 (РЕД ОС), до 14.8.2 (ImageMagick)"),
    # РЕД ОС 8.0 назван прямо — вендор зарегистрировал уязвимость для выпуска хоста
    bdu("BDU:2099-00001", "CVE-2099-0001", "7.3 (РЕД ОС), 8.0 (РЕД ОС), до 7.2 (ImageMagick)"),
    # пакет, по которому у РЕД ОС 8 бюллетеней нет: остаётся с оговоркой
    bdu("BDU:2099-00002", "CVE-2099-0002", "до 4.7 (LibTIFF)"),
]

# бюллетени РЕД ОС 8: ImageMagick вендор ведёт, CVE-2024-0001 закрыта в 7.1.1.30
REDOS_ADV = [Advisory("redos", "8", "ImageMagick", "CVE-2024-0001", FIXED,
                      "7.1.1.30-1.red80", "REDOS-2024-0001")]


class Audit(AuditSink):
    def __init__(self):
        self.records: list[dict] = []

    def record(self, **kw):
        self.records.append(kw)


def run(output: str, advisories):
    store = reference_store()
    store.upsert_bdu(RECORDS)
    mod = AuthInventoryModule(matcher=VulnMatcher(store),
                              connector=lambda h, c, o: FakeShell(output),
                              sleep=lambda s: None, advisories=advisories)
    findings = mod.run(ctx_for(["10.100.12.58"], [cred(1)], Audit()))
    return {f.vuln_id: f for f in findings}


def test_parser_drops_truncated_bounds_and_caps_open_branch():
    [s] = parse_bdu_versions("от 7.0.8 до 68 (ImageMagick)")
    assert s.unknown
    # следующая мажорная версия и год — настоящие границы
    assert parse_bdu_versions("от 4.2.2 до 10 (Android)")[0].end == "10"
    assert parse_bdu_versions("от 7.0 до 2023 (Proficy Historian)")[0].end == "2023"
    open_, closed = parse_bdu_versions(
        "от 6.9.13-28 (ImageMagick), от 7.0.0-0 до 7.1.2-2 (ImageMagick)")
    assert (open_.start, open_.end) == ("6.9.13-28", "7.0.0-0")
    assert (closed.start, closed.end) == ("7.0.0-0", "7.1.2-2")
    # одиночное «от X» без соседней ветки не трогаем
    assert parse_bdu_versions("от 7.0.0 (ImageMagick)")[0].end is None


def test_bdu_release_scope():
    r73 = RECORDS[4]
    assert bduscope.other_release_only(r73, "redos", "8.0")
    assert not bduscope.other_release_only(r73, "redos", "7.3")
    assert not bduscope.other_release_only(RECORDS[0], "redos", "8.0")   # РЕД ОС не назван
    assert bduscope.names_release(RECORDS[5], "redos", "8")
    assert bduscope.same_release("1.7", "1.7.5") and bduscope.same_release("22.04 LTS", "22.04")
    assert not bduscope.same_release("7.3", "8")
    # «до 7.2 Муром» — по такой записи о выпуске хоста судить нельзя
    murom = bdu("BDU:2015-12119", "CVE-2015-0001", "до 7.2 Муром (РЕД ОС), до 1.0 (x)")
    assert bduscope.named_releases(murom, "redos") is None


def test_redos8_imagemagick_false_positives_are_gone():
    before = run(redos_host(IMAGEMAGICK, LIBTIFF), None)
    # без бюллетеней — по версии апстрима, с оговоркой (как раньше)
    assert {"CVE-2015-8894", "CVE-2017-8765", "CVE-2025-57807"} <= set(before)

    found = run(redos_host(IMAGEMAGICK, LIBTIFF), InMemoryAdvisoryStore(REDOS_ADV))
    for cve in ("CVE-2015-8894", "CVE-2017-8765", "CVE-2020-27752", "CVE-2025-55212",
                "CVE-2025-57807"):
        assert cve not in found, cve
    # БДУ прямо называет РЕД ОС 8.0 — остаётся
    assert "CVE-2099-0001" in found
    # по libtiff бюллетеней РЕД ОС 8 нет — как раньше, с оговоркой
    tiff = found["CVE-2099-0002"]
    assert BACKPORT_CAVEAT in tiff.evidence and "Нет данных вендора" in tiff.evidence
    s = found["INFO:auth-inventory"].evidence
    assert "не относится к выпуску — 3" in s


def test_redos73_keeps_its_own_records():
    out = redos_host(IMAGEMAGICK.replace("red80", "el7"), LIBTIFF).replace(
        'VERSION_ID="8.0"', 'VERSION_ID="7.3"').replace('VERSION="8.0"', 'VERSION="7.3"')
    adv = [Advisory("redos", "7.3", "libtiff", "CVE-2024-0002", FIXED, "4.0.9-1.el7")]
    found = run(out, InMemoryAdvisoryStore(adv))
    # на 7.3 запись «7.3 (РЕД ОС)» относится к хосту: ImageMagick вендор здесь не
    # ведёт, решения нет — находка остаётся с оговоркой
    assert "CVE-2025-57807" in found
