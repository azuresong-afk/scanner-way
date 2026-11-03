"""План исправлений для администраторов (вкладка «Находки», режим «Что исправить»)."""
from __future__ import annotations

from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.reporting.fixplan import (
    build_fix_plan,
    kernel_commands,
    package_commands,
    safe_packages,
)
from scanner.reporting.remediation import HostOs, RemediationResolver


def _pkg(host: str, cve: str, *, names="libssl3, openssl", installed="3.0.11-1~deb12u1",
         fixed="3.0.15-1~deb12u1", src="Debian bookworm", adv="DSA-5532-1",
         pkg="openssl", sev=Severity.HIGH) -> Finding:
    return Finding(
        module="auth_inventory", host=host, finding_type=FindingType.VULN,
        vuln_id=cve, cve_ids=[cve], severity=sev,
        title=f"{cve}: пакет openssl {installed} (исправлено в {fixed})",
        evidence=(f"Пакет {names} ({installed}) → OpenSSL 3.0.11\n"
                  f"Бюллетень {src} ({adv}): {cve} исправлена в версии {fixed} "
                  f"(пакет {pkg}); установлена {installed} — пакет уязвим, обновите его "
                  "из репозитория дистрибутива."))


def _ids(findings):
    return list(enumerate(findings, start=1))


DEB = {"10.0.0.1": "Debian GNU/Linux 12 (bookworm)", "10.0.0.2": "Debian GNU/Linux 12 (bookworm)",
       "10.0.0.3": "РЕД ОС 7.3", "10.0.0.4": "Astra Linux 1.7_x86-64"}


def test_package_updates_grouped_per_os_and_package():
    fs = [_pkg("10.0.0.1", "CVE-2023-5678"),
          _pkg("10.0.0.2", "CVE-2023-5678"),
          _pkg("10.0.0.2", "CVE-2024-0727", fixed="3.0.13-1~deb12u1", adv="DSA-5600-1",
               sev=Severity.MEDIUM)]
    plan = build_fix_plan(_ids(fs), resolver=RemediationResolver(host_os=DEB),
                          managers={"10.0.0.1": "dpkg", "10.0.0.2": "dpkg"})
    assert len(plan) == 1
    t = plan[0]
    assert t.kind == "package" and t.os == "Debian 12" and t.manager == "dpkg"
    # наибольшая исправленная версия по правилам dpkg
    assert t.fixed_version == "3.0.15-1~deb12u1"
    assert t.packages == ["libssl3", "openssl"]
    assert t.title == "Обновить libssl3, openssl до 3.0.15-1~deb12u1"
    assert t.commands == ["sudo apt-get update",
                          "sudo apt-get install --only-upgrade -y libssl3 openssl"]
    assert t.verify == ["dpkg-query -W -f='${Package} ${Version}\\n' libssl3 openssl"]
    assert t.advisories == ["DSA-5532-1", "DSA-5600-1"]
    assert t.cves == ["CVE-2023-5678", "CVE-2024-0727"]
    assert [h.host for h in t.hosts] == ["10.0.0.1", "10.0.0.2"]
    assert t.hosts[1].installed == "3.0.11-1~deb12u1"
    assert [x.label for x in t.hosts[1].findings] == ["CVE-2023-5678", "CVE-2024-0727"]
    assert t.severity is Severity.HIGH
    assert any("needrestart" in s for s in t.steps)          # библиотека — перезапуск служб
    assert "repo" not in t.to_dict()                           # контракт без лишних полей
    assert t.to_dict()["host_count"] == 2 and t.to_dict()["finding_count"] == 3


def test_same_package_on_different_os_gives_separate_tasks():
    fs = [_pkg("10.0.0.1", "CVE-2023-5678"),
          _pkg("10.0.0.3", "CVE-2023-5678", names="openssl-libs", installed="1:3.0.7-1.el7",
               fixed="1:3.0.7-5.el7", src="РЕД ОС 7.3", adv="ROS-2024-01",
               pkg="openssl-libs")]
    plan = build_fix_plan(_ids(fs), resolver=RemediationResolver(host_os=DEB),
                          managers={"10.0.0.1": "dpkg", "10.0.0.3": "rpm"})
    by_os = {t.os: t for t in plan}
    assert set(by_os) == {"Debian 12", "РЕД ОС 7.3"}
    red = by_os["РЕД ОС 7.3"]
    assert red.commands == ["sudo yum update -y openssl-libs"]     # РЕД ОС 7.x — yum
    assert red.verify == ["rpm -q openssl-libs"]


def test_unsafe_package_names_give_no_commands():
    assert safe_packages(["openssl", "x; rm -rf /"]) is None
    assert safe_packages(["libssl3:amd64", "g++-12"]) == ["libssl3:amd64", "g++-12"]
    f = _pkg("10.0.0.1", "CVE-2023-5678", names="$(reboot)")
    t = build_fix_plan(_ids([f]), resolver=RemediationResolver(host_os=DEB),
                       managers={"10.0.0.1": "dpkg"})[0]
    assert t.commands == [] and t.verify == []
    assert t.steps                                       # текстовое действие остаётся


def test_package_commands_per_family():
    assert package_commands(HostOs("redos", "8"), "rpm", ["curl"])[0] == [
        "sudo dnf upgrade -y --refresh curl"]
    assert package_commands(HostOs("alt", "p10"), "rpm", ["curl"])[0] == [
        "apt-get update", "apt-get install curl"]
    assert package_commands(HostOs("alpine", "3.19"), "apk", ["curl"]) == (
        ["apk update", "apk upgrade curl"], ["apk info -v curl"])
    assert package_commands(HostOs("astra", "1.7"), "dpkg", ["curl"])[0][1] == (
        "sudo apt-get install --only-upgrade -y curl")
    assert package_commands(None, None, ["curl"]) == ([], [])


def test_kernel_update_and_reboot_only():
    head = "Пакет linux-image-6.1.0-18-amd64 (6.1.76-1) → Ядро Linux 6.1.0-18-amd64"
    vuln = Finding(
        module="auth_inventory", host="10.0.0.1", finding_type=FindingType.VULN,
        vuln_id="CVE-2024-1086", cve_ids=["CVE-2024-1086"], severity=Severity.HIGH,
        title="CVE-2024-1086: ядро Linux 6.1.0-18-amd64 (исправлено в 6.1.85-1)",
        evidence=f"{head}\nБюллетень Debian bookworm (DSA-5658-1): CVE-2024-1086 "
                 "исправлена в ядре версии 6.1.85-1; работает ядро 6.1.0-18-amd64 "
                 "(версия 6.1.76-1) — уязвимо.")
    reboot = Finding(
        module="auth_inventory", host="10.0.0.2", finding_type=FindingType.CONFIG,
        vuln_id="KERNEL-REBOOT-PENDING", severity=Severity.MEDIUM,
        title="Обновлённое ядро установлено, но не загружено: работает 6.1.0-18-amd64",
        evidence=f"{head}\nУстановлено более новое ядро 6.1.0-21-amd64 (пакет "
                 "linux-image-6.1.0-21-amd64 6.1.90-1), но хост с него не загружен.")
    plan = build_fix_plan(_ids([vuln, reboot]), resolver=RemediationResolver(host_os=DEB),
                          managers={"10.0.0.1": "dpkg", "10.0.0.2": "dpkg"})
    assert len(plan) == 1
    t = plan[0]
    assert t.kind == "kernel" and t.reboot
    assert t.title == "Обновить ядро Linux и перезагрузить (Debian 12)"
    assert t.fixed_version == "6.1.85-1"
    assert t.commands[-1] == "sudo reboot" and t.verify == ["uname -r"]
    notes = {h.host: (h.installed, h.note) for h in t.hosts}
    assert notes["10.0.0.1"] == ("6.1.0-18-amd64", "обновить ядро и перезагрузить")
    assert notes["10.0.0.2"] == ("6.1.0-18-amd64",
                                 "только перезагрузка — загрузится 6.1.0-21-amd64")
    # только перезагрузка
    only = build_fix_plan(_ids([reboot]), resolver=RemediationResolver(host_os=DEB))[0]
    assert only.commands == ["sudo reboot"]
    assert only.title.startswith("Перезагрузить хосты")
    assert kernel_commands(HostOs("alt", "p10"), "rpm", False)[0] == ["update-kernel",
                                                                     "sudo reboot"]


def test_nofix_upgrade_software_config_and_cred():
    nofix = Finding(
        module="auth_inventory", host="10.0.0.4", finding_type=FindingType.VULN,
        vuln_id="CVE-2024-9999", cve_ids=["CVE-2024-9999"], severity=Severity.MEDIUM,
        title="CVE-2024-9999: пакет curl",
        evidence="Пакет curl (7.88.1-10+deb12u5) → curl 7.88.1\nБюллетень Astra Linux 1.7: "
                 "исправления CVE-2024-9999 для пакета curl у вендора пока нет — пакет уязвим.")
    upstream = Finding(
        module="auth_inventory", host="10.0.0.3", finding_type=FindingType.VULN,
        vuln_id="CVE-2024-1111", cve_ids=["CVE-2024-1111"], severity=Severity.HIGH,
        title="CVE-2024-1111: nginx 1.20.1",
        evidence="Пакет nginx (1:1.20.1-1.el7) → nginx 1.20.1")
    banner = Finding(
        module="vuln", host="10.0.0.5", port=80, finding_type=FindingType.VULN,
        vuln_id="CVE-2021-41773", cve_ids=["CVE-2021-41773"], severity=Severity.CRITICAL,
        title="Apache HTTP Server 2.4.49 path traversal")
    config = Finding(
        module="config_audit", host="10.0.0.1", finding_type=FindingType.CONFIG,
        vuln_id="SSH-PERMIT-ROOT", severity=Severity.MEDIUM,
        title="Разрешён вход root по SSH",
        remediation="Задайте PermitRootLogin no в /etc/ssh/sshd_config и перезапустите sshd.")
    cred = Finding(
        module="cred_audit", host="10.0.0.6", port=22, finding_type=FindingType.CRED,
        vuln_id="CRED:ssh", severity=Severity.CRITICAL, title="Подобран пароль SSH: admin")
    info = Finding(module="discovery", host="10.0.0.1", finding_type=FindingType.INFO,
                   title="Открыт порт 22")
    services = {("10.0.0.5", 80): ServiceInfo(host="10.0.0.5", port=80, protocol="tcp",
                                               service="http", product="Apache httpd",
                                               version="2.4.49")}
    plan = build_fix_plan(_ids([nofix, upstream, banner, config, cred, info]),
                          resolver=RemediationResolver(host_os=DEB), services=services,
                          managers={"10.0.0.3": "rpm", "10.0.0.4": "dpkg"})
    kinds = {t.kind: t for t in plan}
    assert set(kinds) == {"package_nofix", "package_upgrade", "software", "config", "cred"}
    assert kinds["package_nofix"].title == "Нет исправления: curl (Astra Linux 1.7)"
    assert kinds["package_nofix"].commands == []
    up = kinds["package_upgrade"]
    assert up.commands == ["sudo yum update -y nginx"] and up.fixed_version is None
    sw = kinds["software"]
    assert sw.title == "Обновить Apache httpd"
    assert sw.hosts[0].installed == "2.4.49" and sw.hosts[0].ports == [80]
    assert kinds["config"].steps[0].startswith("Задайте PermitRootLogin no")
    assert kinds["config"].details_source == "Правило бенчмарка"
    assert kinds["cred"].steps[0].startswith("Немедленно смените пароль")
    assert kinds["cred"].title.startswith("Сменить учётные данные")
    # критичные — первыми (приоритеты не заданы — по уровню)
    assert plan[0].severity is Severity.CRITICAL


def test_no_exploit_links_in_references():
    class Bdu:
        bdu_id = "BDU:2023-01234"
        remediation = "Обновите пакет."
        fix_method = "Обновление программного обеспечения"
        cve_ids = ("CVE-2023-5678",)
        refs = ("https://www.exploit-db.com/exploits/1\n"
                "https://www.debian.org/security/2023/dsa-5532")
    f = _pkg("10.0.0.1", "CVE-2023-5678")
    t = build_fix_plan(_ids([f]), resolver=RemediationResolver(
        bdu={"BDU:2023-01234": Bdu()}, host_os=DEB))[0]
    assert t.references and not any("exploit" in u for u in t.references)


# --- API -------------------------------------------------------------------------

def test_api_fix_plan_filters_and_false_positives(sqlite_factory):
    from scanner.core import repository as repo
    from scanner.core.db import session_scope
    from tests.test_pagination import PASSWORD, _admin_can_view, _client, _login

    fs = [_pkg("10.0.0.1", "CVE-2023-5678"), _pkg("10.0.0.2", "CVE-2023-5678"),
          Finding(module="config_audit", host="10.0.0.1", finding_type=FindingType.CONFIG,
                  vuln_id="SSH-PERMIT-ROOT", severity=Severity.MEDIUM,
                  title="Разрешён вход root по SSH", remediation="PermitRootLogin no")]
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="Ромашка")
        rid = repo.create_scan_run(s, engagement_id=eid, modules=["auth_inventory"],
                                   targets=["10.0.0.0/24"], name="прогон")
        repo.set_scan_run_status(s, rid, "done")
        repo.save_findings(s, engagement_id=eid, scan_run_id=rid, findings=fs)
    with _client(sqlite_factory) as c:
        h = _admin_can_view(c, _login(c))
        r = c.get(f"/runs/{rid}/fixes", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["tasks"] == 2 and body["hosts"] == 2 and body["findings"] == 3
        assert body["kinds"] == {"package": 1, "config": 1}
        pkg = next(t for t in body["items"] if t["kind"] == "package")
        assert pkg["fixed_version"] == "3.0.15-1~deb12u1"
        # ОС берётся из строки бюллетеня; менеджер — по семейству ОС
        assert pkg["os"] == "Debian 12" and pkg["commands"][0] == "sudo apt-get update"
        assert [x["host"] for x in pkg["hosts"]] == ["10.0.0.1", "10.0.0.2"]

        only = c.get(f"/runs/{rid}/fixes", headers=h, params={"kind": "config"}).json()
        assert only["total"] == 1 and only["items"][0]["steps"][0] == "PermitRootLogin no"
        assert c.get(f"/runs/{rid}/fixes", headers=h,
                     params={"q": "dsa-5532"}).json()["total"] == 1
        assert c.get(f"/runs/{rid}/fixes", headers=h,
                     params={"host": "10.0.0.2"}).json()["total"] == 1

        # карточка находки из плана; отметка «ложное» убирает хост из действия
        fid = pkg["hosts"][1]["findings"][0]["id"]
        one = c.get(f"/findings/{fid}", headers=h)
        assert one.status_code == 200 and one.json()["host"] == "10.0.0.2"
        assert c.get("/findings/999999", headers=h).status_code == 404
        c.post("/users", headers=_login(c), json={"username": "op", "password": PASSWORD,
                                                   "roles": ["operator"]})
        op = {"Authorization": "Bearer " + c.post("/auth/token", json={
            "username": "op", "password": PASSWORD}).json()["access_token"]}
        assert c.put(f"/findings/{fid}/false-positive", headers=op,
                     json={"reason": "бэкпорт"}).status_code == 200
        after = c.get(f"/runs/{rid}/fixes", headers=h).json()
        assert after["false_positives"] == 1
        pkg = next(t for t in after["items"] if t["kind"] == "package")
        assert [x["host"] for x in pkg["hosts"]] == ["10.0.0.1"]
