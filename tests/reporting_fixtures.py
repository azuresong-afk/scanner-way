"""Фикстура находок для тестов отчётов: два прогона по нескольким модулям."""
from datetime import UTC, datetime

from scanner.core.models import Finding, FindingType, Severity
from scanner.feeds.bdu_fstec import BduRecord
from scanner.reporting.remediation import RemediationResolver

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

BDU_REMEDIATION = "Обновление программного обеспечения до версии 9.3p2 или выше"


def _vuln(host, port, cve, sev, cvss, title, bdu=None, at=T1, evidence=None):
    return Finding(module="vuln", host=host, port=port, finding_type=FindingType.VULN,
                   title=title, severity=sev, vuln_id=cve, cve_ids=[cve],
                   bdu_ids=[bdu] if bdu else [], cvss=cvss, detected_at=at,
                   evidence=evidence)


def _cfg(host, rule, sev, title, at=T1):
    return Finding(module="config_audit", host=host, finding_type=FindingType.CONFIG,
                   title=title, severity=sev, vuln_id=rule, detected_at=at)


def _cred(host, port, sev, title, at=T1):
    return Finding(module="cred_audit", host=host, port=port, finding_type=FindingType.CRED,
                   title=title, severity=sev, vuln_id="weak-password:ssh", detected_at=at)


def previous_run() -> list[Finding]:
    return [
        _vuln("10.0.0.1", 22, "CVE-2023-38408", Severity.CRITICAL, 9.8,
              "OpenSSH: удалённое выполнение кода через ssh-agent", "BDU:2023-04110", at=T0),
        _vuln("10.0.0.2", 443, "CVE-2022-0778", Severity.HIGH, 7.5,
              "OpenSSL: отказ в обслуживании в BN_mod_sqrt", at=T0),
        _cfg("10.0.0.1", "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
             Severity.MEDIUM, "Разрешён вход root по SSH", at=T0),
    ]


def current_run() -> list[Finding]:
    return [
        # open: был и остался
        _vuln("10.0.0.1", 22, "CVE-2023-38408", Severity.CRITICAL, 9.8,
              "OpenSSH: удалённое выполнение кода через ssh-agent", "BDU:2023-04110",
              evidence="SSH-2.0-OpenSSH_8.9p1 <script>alert(1)</script>\x00"),
        # new: CVE без записи БДУ в finding, но есть связь CVE->БДУ в справочнике
        _vuln("10.0.0.3", 80, "CVE-2021-41773", Severity.CRITICAL, 9.8,
              "Apache HTTP Server: обход каталога"),
        # regression: был устранён ранее и вернулся
        _vuln("10.0.0.4", 3389, "CVE-2019-0708", Severity.HIGH, 9.8,
              "RDP: BlueKeep"),
        # open
        _cfg("10.0.0.1", "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
             Severity.MEDIUM, "Разрешён вход root по SSH"),
        # new, без правила в справочнике -> типовая рекомендация
        _cfg("10.0.0.2", "lynis:AUTH-9286", Severity.LOW, "Не задан максимальный срок пароля"),
        # new
        _cred("10.0.0.5", 22, Severity.HIGH, "Стандартный пароль admin/admin на SSH"),
        Finding(module="discovery", host="10.0.0.5", port=23, finding_type=FindingType.INFO,
                title="Открыт Telnet", severity=Severity.INFO, vuln_id="svc:telnet",
                detected_at=T1),
    ]
    # fixed: CVE-2022-0778 на 10.0.0.2 исчезла


def historically_fixed() -> set[str]:
    return {_vuln("10.0.0.4", 3389, "CVE-2019-0708", Severity.HIGH, 9.8, "RDP").dedup_key()}


def resolver() -> RemediationResolver:
    bdu = {
        "BDU:2023-04110": BduRecord(
            bdu_id="BDU:2023-04110", remediation=BDU_REMEDIATION,
            fix_method="Обновление программного обеспечения",
            cve_ids=["CVE-2023-38408"], cwe="CWE-428",
            refs="https://www.openssh.com/txt/release-9.3p2\n"
                 "https://www.exploit-db.com/exploits/51757\n"
                 "https://github.com/openssh/openssh-portable\n"
                 "https://security-tracker.debian.org/tracker/CVE-2023-38408\n"
                 "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1018SE17"),
        "BDU:2021-04880": BduRecord(
            bdu_id="BDU:2021-04880",
            remediation="Обновление Apache HTTP Server до версии 2.4.51",
            cve_ids=["CVE-2021-41773"], cwe="CWE-22",
            refs="https://httpd.apache.org/security/vulnerabilities_24.html\n"
                 "https://www.securitylab.ru/news/526063.php"),
    }
    nvd = {"CVE-2019-0708": "Install the Microsoft security update KB4499175; disable RDP "
                            "or enable Network Level Authentication."}
    benchmark = {"xccdf_org.ssgproject.content_rule_sshd_disable_root_login":
                 "Установите PermitRootLogin no в /etc/ssh/sshd_config и перезапустите sshd."}
    nvd_refs = {"CVE-2019-0708": [
        "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
        "http://packetstormsecurity.com/files/153133/BlueKeep.html"]}
    return RemediationResolver(bdu=bdu, nvd=nvd, benchmark=benchmark, nvd_refs=nvd_refs)
