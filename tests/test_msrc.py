"""Справочник обновлений Microsoft (feeds/msrc.py): разбор CVRF и сопоставление."""
from __future__ import annotations

from scanner.feeds.msrc import (
    InMemoryMsrcStore,
    MsrcFix,
    WindowsOs,
    assess,
    build_fixed,
    covered_kbs,
    is_windows_product,
    msrc_products,
    parse_cvrf,
    release_key,
)

SERVER2019 = "Windows Server 2019"
PID = "11569"


def _doc() -> dict:
    """Минимальный документ CVRF с одним продуктом Windows и двумя CVE."""
    return {
        "DocumentTracking": {"Identification": {"ID": {"Value": "2024-Jan"}}},
        "ProductTree": {"FullProductName": [
            {"ProductID": PID, "Value": SERVER2019},
            {"ProductID": "99999", "Value": "Microsoft Office"},   # не Windows
        ]},
        "Vulnerability": [
            {"CVE": "CVE-2024-0001", "Title": {"Value": "RCE в компоненте"},
             "Threats": [{"Type": 3, "ProductID": [PID],
                          "Description": {"Value": "Critical"}}],
             "CVSSScoreSets": [{"BaseScore": 9.8, "ProductID": [PID]}],
             "Remediations": [
                 {"Type": 2, "Description": {"Value": "5034127"}, "ProductID": [PID],
                  "Supercedence": "5033420", "FixedBuild": "10.0.17763.5329",
                  "URL": "https://catalog.update.microsoft.com/x"},
                 {"Type": 0, "Description": {"Value": "Release Notes"},
                  "ProductID": [PID]},                       # не Vendor Fix — пропустить
             ]},
            {"CVE": "CVE-2024-0002", "Title": {"Value": "Повышение привилегий"},
             "Threats": [{"Type": 3, "ProductID": [PID],
                          "Description": {"Value": "Important"}}],
             "Remediations": [
                 {"Type": 2, "Description": {"Value": "5034127"}, "ProductID": [PID],
                  "Supercedence": "5033420"},
                 # для не-Windows продукта исправление должно игнорироваться
                 {"Type": 2, "Description": {"Value": "5099999"}, "ProductID": ["99999"]},
             ]},
        ],
    }


def test_parse_cvrf_keeps_only_windows_products():
    fixes = parse_cvrf(_doc())
    assert all(is_windows_product(f.product) for f in fixes)
    by_cve = {f.cve_id: f for f in fixes}
    assert set(by_cve) == {"CVE-2024-0001", "CVE-2024-0002"}
    f1 = by_cve["CVE-2024-0001"]
    assert f1.kb == "5034127" and f1.supersedes == ("5033420",)
    assert f1.fixed_build == "10.0.17763.5329" and f1.severity == "Critical"
    assert f1.cvss == 9.8 and f1.release == "2024-Jan"
    # исправление для Office (не Windows) не попало
    assert all(f.product == SERVER2019 for f in fixes)
    assert "5099999" not in {f.kb for f in fixes}


def test_release_key_orders_bulletins():
    assert release_key("2023-Dec") < release_key("2024-Jan")
    assert release_key("2024-Jan") < release_key("2024-Feb")


def test_msrc_products_for_server_core():
    os = WindowsOs(product_name=SERVER2019, installation_type="Server Core",
                   build=17763, ubr=5329, arch="AMD64")
    names = msrc_products(os)
    assert names[0] == f"{SERVER2019} (Server Core installation)"
    assert SERVER2019 in names


def test_covered_kbs_follows_supersedence_chain():
    fixes = [
        MsrcFix("2023-Nov", "CVE-x", PID, SERVER2019, "100", supersedes=("90",)),
        MsrcFix("2023-Dec", "CVE-y", PID, SERVER2019, "110", supersedes=("100",)),
    ]
    # установлено только последнее накопительное 110 — закрывает 100 и 90
    assert covered_kbs(["110"], fixes) == {"110", "100", "90"}


def test_build_fixed_compares_same_branch():
    assert build_fixed("10.0.17763.5329", "10.0.17763.5329")
    assert build_fixed("10.0.17763.6000", "10.0.17763.5329")
    assert not build_fixed("10.0.17763.5000", "10.0.17763.5329")
    assert not build_fixed("10.0.19041.1", "10.0.17763.5329")   # другая ветка


def test_assess_reports_gap_until_kb_or_build():
    store = InMemoryMsrcStore([
        MsrcFix("2024-Jan", "CVE-2024-0001", PID, SERVER2019, "5034127",
                supersedes=("5033420",), fixed_build="10.0.17763.5329",
                severity="Critical", cvss=9.8),
    ])
    os = WindowsOs(product_name=SERVER2019, installation_type="Server",
                   build=17763, ubr=100, arch="AMD64")
    # ничего не установлено и сборка ниже FixedBuild -> уязвимость открыта
    a = assess(os, [], store)
    assert not a.no_data and a.product == SERVER2019
    assert [g.cve_id for g in a.gaps] == ["CVE-2024-0001"]
    gap = a.gaps[0]
    assert gap.recommended_kb == "5034127" and gap.severity == "Critical"

    # установлена замещающая KB -> закрыто
    assert assess(os, ["KB5034127"], store).gaps == []
    # замещаемая KB (через supersedence) тоже закрывает
    newer = InMemoryMsrcStore([
        MsrcFix("2024-Jan", "CVE-2024-0001", PID, SERVER2019, "5034127",
                supersedes=("5033420",), fixed_build="10.0.17763.5329"),
        MsrcFix("2024-Feb", "CVE-2024-0002", PID, SERVER2019, "5034765",
                supersedes=("5034127",)),
    ])
    assert assess(os, ["KB5034765"], newer).gaps == []    # 5034765 замещает 5034127

    # сборка хоста не ниже FixedBuild -> закрыто даже без известной KB
    patched = WindowsOs(product_name=SERVER2019, installation_type="Server",
                        build=17763, ubr=5329, arch="AMD64")
    assert assess(patched, [], store).gaps == [] and assess(patched, [], store).fixed == 1


def test_assess_no_data_when_product_unknown():
    store = InMemoryMsrcStore([
        MsrcFix("2024-Jan", "CVE-2024-0001", PID, SERVER2019, "5034127"),
    ])
    # сборка есть, но справочника по этому продукту нет
    os = WindowsOs(product_name="Windows Server 2022", installation_type="Server",
                   build=20348, ubr=1, arch="AMD64")
    a = assess(os, [], store)
    assert a.no_data and a.gaps == [] and a.reason
