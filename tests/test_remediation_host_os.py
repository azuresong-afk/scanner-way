"""Рекомендации и ссылки на устранение привязаны к ОС хоста."""
from scanner.core.models import Finding, FindingType, Severity
from scanner.feeds.bdu_fstec import BduRecord
from scanner.reporting.model import build_report
from scanner.reporting.remediation import (
    HostOs,
    RemediationResolver,
    RemediationSource,
    curate_refs,
    describe_ref,
    host_os_from_findings,
    localize_bdu_text,
    vendor_action,
)
from scanner.reporting.render import ReportRenderer

# Фрагмент «Возможные меры по устранению» из реальной записи БДУ (сокращён)
BDU_TEXT = (
    "Установка обновлений из доверенных источников.\n"
    "Компенсирующие меры:\n- использование средств межсетевого экранирования.\n"
    "Использование рекомендаций: Для OpenSSH: https://github.com/openssh/openssh-portable/"
    "commit/892506b1 Для Debian GNU/Linux: https://security-tracker.debian.org/tracker/"
    "CVE-2023-38408 Для программных продуктов Red Hat Inc.: https://access.redhat.com/"
    "security/cve/CVE-2023-38408 Для Ubuntu: https://ubuntu.com/security/notices/USN-6242-1 "
    "Для ОС Astra Linux Special Edition 1.7: обновить пакет openssh до 1:8.4p1-2~deb10u1"
    "astra6se9+ci1 или более высокой версии: https://wiki.astralinux.ru/"
    "astra-linux-se17-bulletin-2023-1023SE17 Для РедОС: http://repo.red-soft.ru/redos/7.3c/"
    "x86_64/updates/ Для Astra Linux Special Edition 4.7: обновить пакет openssh до "
    "1:8.4p1-2~deb10u1astra6se9+ci1: https://wiki.astralinux.ru/"
    "astra-linux-se47-bulletin-2024-0416SE47 Для ОС Альт 8 СП: установка обновления из "
    "публичного репозитория")
REFS = ("https://news.ycombinator.com/item?id=36790196\n"
        "https://www.openssh.com/txt/release-9.3p2\n"
        "https://security-tracker.debian.org/tracker/CVE-2023-38408\n"
        "https://access.redhat.com/security/cve/CVE-2023-38408\n"
        "https://ubuntu.com/security/notices/USN-6242-1\n"
        "https://wiki.astralinux.ru/astra-linux-se47-bulletin-2024-0416SE47\n"
        "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1023SE17\n"
        "https://abf.rosa.ru/advisories/ROSA-SA-2023-2229\n"
        "https://content.kaspersky-labs.com/fm/report.pdf\n"
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38408")
REC = BduRecord(bdu_id="BDU:2023-03950", remediation=BDU_TEXT,
                fix_method="Обновление программного обеспечения",
                cve_ids=["CVE-2023-38408"], cwe="CWE-94", refs=REFS)
ASTRA, UBUNTU, NOOS = "10.0.0.31", "10.0.0.21", "10.0.0.99"
VENDOR_LINE = ("Бюллетень Astra Linux 1.7: CVE-2023-38408 исправлена в версии "
               "1:7.9p1-10+deb10u2+ci202308 (пакет openssh); установлена "
               "1:7.9p1-10+deb10u2+ci202212 — пакет уязвим, обновите его из репозитория "
               "дистрибутива.")


def vuln(host: str, evidence: str | None = None) -> Finding:
    return Finding(module="auth_inventory", host=host, finding_type=FindingType.VULN,
                   title="Уязвимость ssh-agent OpenSSH", severity=Severity.CRITICAL,
                   vuln_id="CVE-2023-38408", cve_ids=["CVE-2023-38408"],
                   bdu_ids=["BDU:2023-03950"], cvss=9.8, evidence=evidence)


def summary(host: str, os_name: str) -> Finding:
    return Finding(module="auth_inventory", host=host, finding_type=FindingType.INFO,
                   title="Инвентаризация", vuln_id="INFO:auth-inventory",
                   evidence=f"ОС: {os_name}\nпакетов: 900 (dpkg)")


def test_host_os_family_and_release():
    assert HostOs.of("Astra Linux 1.7_x86-64 (1.7.5)") == HostOs("astra", "1.7")
    assert HostOs.of("RED OS 8.0") == HostOs("redos", "8")
    assert HostOs.of("РЕД ОС 7.3") == HostOs("redos", "7.3")
    assert HostOs.of("Ubuntu 22.04.4 LTS") == HostOs("ubuntu", "22.04")
    assert HostOs.of("Debian bookworm") == HostOs("debian", "12")
    # версия OpenSSH из баннера — не выпуск Debian
    assert HostOs.of("OpenSSH 9.2p1 Debian 2+deb12u2") == HostOs("debian", "12")
    assert HostOs.of("Linux 4.15 - 5.8") is None and HostOs.of("Windows") is None


def test_localize_keeps_only_host_os_and_release():
    astra = localize_bdu_text(BDU_TEXT, HostOs("astra", "1.7"))
    assert "Special Edition 1.7" in astra and "Компенсирующие меры" in astra
    for other in ("4.7", "Debian", "Red Hat", "Ubuntu", "РедОС", "Альт", "Для OpenSSH"):
        assert other not in astra, other
    deb = localize_bdu_text(BDU_TEXT, HostOs("debian", "12"))
    assert "Для Debian GNU/Linux" in deb and "Astra" not in deb
    # РЕД ОС 8: в записи только репозиторий 7.3 — фрагмент чужого выпуска не берётся,
    # остаются меры производителя ПО, если они про эту находку
    redos8 = localize_bdu_text(BDU_TEXT, HostOs("redos", "8"), context="OpenSSH 9.3p2")
    assert "7.3c" not in redos8 and "Для OpenSSH" in redos8
    assert localize_bdu_text("Обновите ПО", HostOs("astra", "1.7")) is None


def test_vendor_action_from_bulletin_line():
    action, src = vendor_action(VENDOR_LINE)
    assert src == "Astra Linux 1.7"
    assert action.startswith("Обновите пакет openssh — до версии 1:7.9p1-10+deb10u2+ci202308")
    nofix = vendor_action("Бюллетень РЕД ОС 8: исправления CVE-1 для пакета gnutls у "
                          "вендора пока нет — пакет уязвим.")
    assert nofix and "пока нет" in nofix[0] and nofix[1] == "РЕД ОС 8"
    assert vendor_action("Пакет x → y 1.0") is None


def test_resolver_uses_host_os_for_text_and_links():
    findings = [vuln(ASTRA, f"Пакет openssh-server → OpenSSH 7.9p1\n{VENDOR_LINE}"),
                vuln(UBUNTU), vuln(NOOS), summary(UBUNTU, "Ubuntu 22.04.4 LTS")]
    r = RemediationResolver(bdu={REC.bdu_id: REC}, host_os=host_os_from_findings(findings))
    assert r.host_os == {UBUNTU: HostOs("ubuntu", "22.04"), ASTRA: HostOs("astra", "1.7")}

    a = r.resolve(findings[0])
    assert a.source is RemediationSource.VENDOR
    assert a.text.splitlines()[0].startswith("Обновите пакет openssh")
    assert "Debian" not in a.text and "4.7" not in a.text
    labels = [describe_ref(u).label for u in a.references]
    assert a.references[0].endswith("2023-1023SE17")           # бюллетень ОС хоста первым
    assert not any(x in " ".join(labels) for x in ("Debian", "Red Hat", "Ubuntu", "РОСА",
                                                   "Microsoft", "ycombinator", "kaspersky"))
    assert not any("se47" in u for u in a.references)

    u = r.resolve(findings[1])
    assert u.source is RemediationSource.BDU and "Для Ubuntu" in u.text
    assert "Astra" not in u.text
    assert u.references[0].startswith("https://ubuntu.com/security/")
    assert not any("astralinux" in x or "debian.org" in x for x in u.references)

    # ОС неизвестна — как раньше: полный текст БДУ, все бюллетени ОС
    n = r.resolve(findings[2])
    assert n.text == BDU_TEXT
    assert any("astralinux" in x for x in n.references)
    assert not any("ycombinator" in x for x in n.references)   # новости — никогда


REDOS = "10.0.0.41"
# Типичный набор ссылок NVD по CVE пакета: бюллетени сторонних продуктов,
# GitHub Advisory и несколько коммитов апстрима.
NVD_REFS = ["https://security.netapp.com/advisory/ntap-20230803-0010/",
            "https://support.apple.com/kb/HT213940",
            "https://www.ibm.com/support/pages/node/7022",
            "https://github.com/openssh/openssh-portable/security/advisories/GHSA-x",
            "https://github.com/openssh/openssh-portable/commit/aaa111",
            "https://github.com/openssh/openssh-portable/commit/bbb222",
            "https://example-vendor.test/sa-2023-01"]


def test_package_vuln_on_known_distro_gets_compact_links():
    """Пакет на известном дистрибутиве: бюллетень ОС, БДУ, NVD и одно исправление."""
    r = RemediationResolver(bdu={REC.bdu_id: REC}, host_os={REDOS: "РЕД ОС 7.3"},
                            nvd_refs={"CVE-2023-38408": NVD_REFS})
    refs = r.resolve(vuln(REDOS)).references
    kinds = [describe_ref(u).kind.name for u in refs]
    assert set(kinds) <= {"OS", "REGISTRY", "PATCH"}
    assert kinds.count("PATCH") == 1
    assert "OS" not in kinds          # бюллетеней других дистрибутивов нет
    assert "https://bdu.fstec.ru/vul/2023-03950" in refs
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-38408" in refs
    assert not any(x in " ".join(refs) for x in ("netapp", "apple", "ibm.com", "advisories",
                                                 "example-vendor", "openssh.com"))

    # ОС не определена или находка не из инвентаря пакетов — набор прежний
    full = r.resolve(vuln(NOOS)).references
    assert any("netapp" in u for u in full)
    other = Finding(module="nuclei", host=REDOS, finding_type=FindingType.VULN,
                    title="OpenSSH", severity=Severity.HIGH, vuln_id="CVE-2023-38408",
                    cve_ids=["CVE-2023-38408"])
    assert any("netapp" in u for u in r.resolve(other).references)


def test_add_host_os_does_not_override_run_data():
    r = RemediationResolver(host_os={ASTRA: "Astra Linux 1.7"})
    r.add_host_os({ASTRA: "Debian 12", NOOS: "Linux 5.x", UBUNTU: "Ubuntu 24.04"},
                  override=False)
    assert r.host_os == {ASTRA: HostOs("astra", "1.7"), UBUNTU: HostOs("ubuntu", "24.04")}


def test_curate_refs_without_host_os_unchanged_order():
    urls = ["https://wiki.astralinux.ru/a", "https://vendor.example/x"]
    assert curate_refs(urls) == ["https://vendor.example/x", "https://wiki.astralinux.ru/a"]
    assert curate_refs(urls, host_os=HostOs("astra", None)) == [
        "https://wiki.astralinux.ru/a", "https://vendor.example/x"]


def test_report_renders_localized_text_with_line_breaks():
    findings = [vuln(ASTRA, VENDOR_LINE)]
    report = build_report(findings, resolver=RemediationResolver(bdu={REC.bdu_id: REC}))
    html = ReportRenderer().render(report, "html").decode()
    assert 'class="fix-text"' in html and "Обновите пакет openssh" in html
    assert "astra-linux-se47" not in html
