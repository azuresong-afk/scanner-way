"""Ложные находки при исправлении вендора (пример с лабы: live555 на РЕД ОС 8).

Прогон №27, хост РЕД ОС 8, пакет live555 2023.03.30-1.red80: CVE-2023-37117 /
BDU:2025-03953 «Вероятно — пакет на хосте» по версии апстрима, «нет данных
вендора». Запись БДУ ниже — дословная выдержка из выгрузки vullist.xlsx: из
дистрибутивов в ней названа только Astra Linux, РЕД ОС нет.

Проверяется:
* журнал изменений пакета (rpm %changelog / changelog.Debian.gz) с CVE или БДУ
  находки закрывает находку по версии апстрима, если бюллетень молчит;
* бюллетень, который ссылается только на БДУ (без CVE), не теряется при разборе
  OVAL и находит находку по её идентификатору БДУ;
* решение бюллетеня «уязвим» журнал изменений не перебивает (нет ложной чистоты).
"""
from __future__ import annotations

import io

from scanner.feeds.advisories.base import FIXED, Advisory
from scanner.feeds.advisories.oval import parse_oval
from scanner.feeds.advisories.redos import parse_redos
from scanner.feeds.advisories.store import InMemoryAdvisoryStore
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import BACKPORT_CAVEAT, VulnMatcher
from scanner.modules.auth_inventory import AuthInventoryModule, parse_changelog_ids
from tests.test_auth_inventory import FakeShell, cred, ctx_for, reference_store
from tests.test_redos_release_scope import REDOS_8, Audit

CRIT = "Критический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)"
LIVE555_BDU = BduRecord(
    bdu_id="BDU:2025-03953", title="Уязвимость компонента Setup Handler Live555",
    versions="1.7 (Astra Linux Special Edition), 4.7 (Astra Linux Special Edition), "
             "до 2023.06.14 (Live555)",
    software="Astra Linux Special Edition (запись в едином реестре российских программ "
             "№369), Live555",
    cve_ids=["CVE-2023-37117"], severity_text=CRIT)
LIVE555 = "live555\t2023.03.30-1.red80\tx86_64\tlive555-2023.03.30-1.red80.src.rpm"
CURL = "curl\t8.4.0-1.red80\tx86_64\tcurl-8.4.0-1.red80.src.rpm"
# бюллетени РЕД ОС 8 загружены, но о live555 в них ничего нет
REDOS_ADV = [Advisory("redos", "8", "curl", "CVE-2024-2398", FIXED, "0:8.7.1-1.red80")]


def host(*rows: str, changelog: str | None = None, end: bool = True) -> str:
    out = f"@@os-release\n{REDOS_8}\n@@rpm\n" + "\n".join(rows) + "\n"
    if changelog is not None:
        out += f"@@changelog\n{changelog}\n"
    return out + ("@@end\n" if end else "")


def run(output: str, advisories, records=(LIVE555_BDU,)):
    store = reference_store()
    store.upsert_bdu(list(records))
    audit = Audit()
    mod = AuthInventoryModule(matcher=VulnMatcher(store),
                              connector=lambda h, c, o: FakeShell(output),
                              sleep=lambda s: None, advisories=advisories)
    findings = mod.run(ctx_for(["10.100.12.58"], [cred(1)], audit))
    return {f.vuln_id: f for f in findings}, audit


def test_lab_case_reproduced_without_vendor_data():
    found, _ = run(host(LIVE555, CURL), InMemoryAdvisoryStore(REDOS_ADV))
    f = found["CVE-2023-37117"]
    assert "BDU:2025-03953" in f.bdu_ids
    assert BACKPORT_CAVEAT in f.evidence
    # причина «нет данных» теперь точнее: о пакете нет НИ ОДНОЙ записи вендора
    assert "нет ни одной записи о пакете live555" in f.evidence


def test_changelog_with_cve_closes_upstream_match():
    log = "=P=curl\nCVE-2023-38545\n=P=live555\nCVE-2023-37117\nCVE-2021-38380"
    found, audit = run(host(LIVE555, CURL, changelog=log), InMemoryAdvisoryStore(REDOS_ADV))
    assert "CVE-2023-37117" not in found
    s = found["INFO:auth-inventory"].evidence
    assert "закрыто по журналу изменений пакета" in s and "CVE-2023-37117" in s
    rec = next(r for r in audit.records if r["action"] == "auth_inventory_backport")
    assert "live555" in rec["details"]["changelog_closed"]["CVE-2023-37117"]


def test_changelog_with_bdu_id_closes_too():
    log = "=P=live555\nBDU:2025-03953"
    found, _ = run(host(LIVE555, changelog=log), InMemoryAdvisoryStore(REDOS_ADV))
    assert "CVE-2023-37117" not in found


def test_changelog_closes_even_without_bulletins():
    log = "=P=live555\nCVE-2023-37117"
    found, _ = run(host(LIVE555, changelog=log), None)
    assert "CVE-2023-37117" not in found
    assert "закрыто по журналу изменений" in found["INFO:auth-inventory"].evidence


def test_changelog_of_other_cve_or_package_keeps_finding():
    log = "=P=live555\nCVE-2021-38380\n=P=curl\nCVE-2023-37117"
    found, _ = run(host(LIVE555, CURL, changelog=log), InMemoryAdvisoryStore(REDOS_ADV))
    assert "CVE-2023-37117" in found
    assert "в журнале изменений пакета CVE-2023-37117 не упоминается" in \
        found["CVE-2023-37117"].evidence


def test_truncated_output_ignores_changelog():
    log = "=P=live555\nCVE-2023-37117"
    found, _ = run(host(LIVE555, changelog=log, end=False), InMemoryAdvisoryStore(REDOS_ADV))
    assert "CVE-2023-37117" in found


def test_vendor_vulnerable_verdict_beats_changelog():
    adv = [*REDOS_ADV, Advisory("redos", "8", "live555", "CVE-2023-37117", FIXED,
                                "2023.03.30-2.red80", "ROS-20250101-01")]
    log = "=P=live555\nCVE-2023-37117"
    found, _ = run(host(LIVE555, changelog=log), InMemoryAdvisoryStore(adv))
    f = found["CVE-2023-37117"]
    assert f.confidence == "high" and "2023.03.30-2.red80" in f.evidence


def test_bdu_only_bulletin_closes_finding():
    adv = [*REDOS_ADV, Advisory("redos", "8", "live555", "BDU:2025-03953", FIXED,
                                "2023.03.30-1.red80", "ROS-20250410-03")]
    found, _ = run(host(LIVE555), InMemoryAdvisoryStore(adv))
    assert "CVE-2023-37117" not in found
    assert "BDU:2025-03953" not in found          # и не добавлена второй раз по БДУ


def test_bdu_only_bulletin_confirms_with_fixed_version():
    adv = [*REDOS_ADV, Advisory("redos", "8", "live555", "BDU:2025-03953", FIXED,
                                "2023.03.30-2.red80", "ROS-20250410-03")]
    found, _ = run(host(LIVE555), InMemoryAdvisoryStore(adv))
    f = found["CVE-2023-37117"]
    assert f.source == "vendor_advisory" and "2023.03.30-2.red80" in f.evidence
    assert "BDU:2025-03953" not in found


def test_bdu_only_bulletin_adds_finding_with_bdu_id():
    adv = [*REDOS_ADV, Advisory("redos", "8", "curl", "BDU:2024-00001", FIXED,
                                "0:8.5.0-1.red80")]
    found, _ = run(host(CURL), InMemoryAdvisoryStore(adv), records=())
    f = found["BDU:2024-00001"]
    assert f.bdu_ids == ["BDU:2024-00001"] and not f.cve_ids


OVAL_BDU_ONLY = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition class="patch" id="oval:ru.redsoft:def:10" version="1">
      <metadata>
        <title>ROS-20250410-03: live555</title>
        <reference ref_id="BDU:2025-03953" source="BDU"/>
        <reference ref_id="2025-04001" source="FSTEC"/>
      </metadata>
      <criteria><criterion comment="live555 is earlier than 0:2023.03.30-2.red80"
        test_ref="tst:10"/></criteria>
    </definition>
    <definition class="patch" id="oval:ru.redsoft:def:11" version="1">
      <metadata>
        <title>ROS-20250410-04: curl</title>
        <reference ref_id="CVE-2024-2398" source="CVE"/>
        <reference ref_id="BDU:2024-02391" source="BDU"/>
      </metadata>
      <criteria><criterion comment="curl is earlier than 0:8.7.1-1.red80"
        test_ref="tst:11"/></criteria>
    </definition>
  </definitions>
  <tests>
    <linux:rpminfo_test id="tst:10"><linux:object object_ref="obj:10"/><linux:state state_ref="ste:10"/></linux:rpminfo_test>
    <linux:rpminfo_test id="tst:11"><linux:object object_ref="obj:11"/><linux:state state_ref="ste:11"/></linux:rpminfo_test>
  </tests>
  <objects>
    <linux:rpminfo_object id="obj:10"><linux:name>live555</linux:name></linux:rpminfo_object>
    <linux:rpminfo_object id="obj:11"><linux:name>curl</linux:name></linux:rpminfo_object>
  </objects>
  <states>
    <linux:rpminfo_state id="ste:10"><linux:evr datatype="evr_string" operation="less than">0:2023.03.30-2.red80</linux:evr></linux:rpminfo_state>
    <linux:rpminfo_state id="ste:11"><linux:evr datatype="evr_string" operation="less than">0:8.7.1-1.red80</linux:evr></linux:rpminfo_state>
  </states>
</oval_definitions>
"""


def test_oval_keeps_bdu_only_definitions():
    recs = list(parse_oval(io.BytesIO(OVAL_BDU_ONLY), "redos", ["8"]))
    ids = {(r.package, r.cve): r for r in recs}
    assert ids[("live555", "BDU:2025-03953")].fixed_version == "0:2023.03.30-2.red80"
    assert ids[("live555", "BDU:2025-03953")].advisory_id == "ROS-20250410-03"
    assert ("live555", "BDU:2025-04001") in ids          # source="FSTEC", без префикса
    # есть CVE — запись по CVE, БДУ не дублируется
    assert ("curl", "CVE-2024-2398") in ids and ("curl", "BDU:2024-02391") not in ids
    # общий файл РЕД ОС: выпуск по метке сборки
    shared = list(parse_redos(io.BytesIO(OVAL_BDU_ONLY), "redos", ["7.3", "8"]))
    assert {r.release for r in shared} == {"8"}


def test_parse_changelog_ids():
    got = parse_changelog_ids(["=P=a", "CVE-2023-1", "CVE-2023-12345", "junk",
                               "=P=b", "=P=c", "BDU:2025-03953"])
    assert got == {"a": {"CVE-2023-12345"}, "c": {"BDU:2025-03953"}}


# ---------- Astra Linux: указание вендора в самой записи БДУ ----------

ASTRA_17 = 'PRETTY_NAME="Astra Linux"\nVERSION_ID=1.7_x86-64\nID=astra\nID_LIKE=debian'
# дословно из «Возможных мер» BDU:2025-03953 (выгрузка vullist.xlsx)
LIVE555_REMEDIATION = (
    "В условиях отсутствия обновлений безопасности от производителя рекомендуется "
    "придерживаться \"Рекомендаций по безопасной настройке операционных систем LINUX\"."
    "\n\nИспользование рекомендаций:\nДля Live555:\n"
    "http://www.live555.com/liveMedia/public/changelog.txt\n\n"
    "Для ОС Astra Linux:\nобновить пакет liblivemedia до 2:2024.11.28-1.astra1+ci3 или "
    "более высокой версии, используя рекомендации производителя: "
    "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2025-0319SE17\n\n"
    "Для ОС Astra Linux:\nобновить пакет liblivemedia до 2:2024.11.28-1.astra1+ci3 или "
    "более высокой версии, используя рекомендации производителя: "
    "https://wiki.astralinux.ru/astra-linux-se47-bulletin-2025-0422SE47")
LIVE555_ASTRA_BDU = BduRecord(
    bdu_id=LIVE555_BDU.bdu_id, title=LIVE555_BDU.title, versions=LIVE555_BDU.versions,
    software=LIVE555_BDU.software, cve_ids=list(LIVE555_BDU.cve_ids),
    severity_text=CRIT, remediation=LIVE555_REMEDIATION)


def astra_host(version: str, release: str = "1.7_x86-64") -> str:
    # бинарный пакет назван live555, чтобы его нашло сопоставление по имени ПО БДУ;
    # указание вендора дано по исходному пакету liblivemedia
    osr = ASTRA_17.replace("1.7_x86-64", release)
    pkg = (f"install ok installed\tlive555\t{version}\tamd64\tliblivemedia\t"
           f"{version}")
    return f"@@os-release\n{osr}\n@@dpkg\n{pkg}\n@@end\n"


def test_bdu_remediation_parser():
    from scanner.feeds.advisories.bdufix import astra_fixes, astra_rows
    fx = astra_fixes(LIVE555_REMEDIATION)
    assert [(r, p, v) for r, p, v, _ in fx] == [
        ("1.7", "liblivemedia", "2:2024.11.28-1.astra1+ci3"),
        ("4.7", "liblivemedia", "2:2024.11.28-1.astra1+ci3")]
    assert [r.release for r in astra_rows(LIVE555_REMEDIATION, "CVE-1", "1.7")] == ["1.7"]
    assert astra_rows(LIVE555_REMEDIATION, "CVE-1", "1.8") == []
    head = astra_fixes("Для ОС Astra Linux Special Edition для «Эльбрус» 8.1 «Ленинград»:\n"
                       "обновить пакет glibc до 2.29-26.018-astra1 или более высокой версии")
    assert head[0][0] == "elbrus-8.1"


def test_astra_backport_closed_and_old_build_confirmed():
    rec = BduRecord(
        bdu_id=LIVE555_BDU.bdu_id, title=LIVE555_BDU.title,
        versions="до 2023.06.14 (Live555)", software="Live555",
        cve_ids=["CVE-2023-37117"], severity_text=CRIT,
        remediation=LIVE555_REMEDIATION.replace("2:2024.11.28-1.astra1+ci3",
                                                "2:2020.01.11-5.astra1+ci2"))
    closed, _ = run(astra_host("2:2020.01.11-5.astra1+ci2"), None, records=(rec,))
    assert "CVE-2023-37117" not in closed
    assert "закрыто по указанию вендора в записи БДУ ФСТЭК — 1" in \
        closed["INFO:auth-inventory"].evidence
    old, _ = run(astra_host("2:2020.01.11-5.astra1+ci1"), None, records=(rec,))
    f = old["CVE-2023-37117"]
    assert f.confidence == "high" and "2:2020.01.11-5.astra1+ci2" in f.evidence
    assert BACKPORT_CAVEAT not in f.evidence
    # указание другого выпуска (1.7/4.7) к Astra 1.8 не относится — как раньше
    other, _ = run(astra_host("2:2020.01.11-5.astra1+ci2", "1.8_x86-64"), None,
                   records=(rec,))
    assert BACKPORT_CAVEAT in other["CVE-2023-37117"].evidence
