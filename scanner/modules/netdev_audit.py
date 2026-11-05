"""Модуль: аудит сетевого оборудования по учётной записи (SSH-CLI и SNMP).

Коммутаторы, маршрутизаторы и межсетевые экраны (Cisco IOS / IOS XE / NX-OS /
ASA, Juniper Junos, MikroTik RouterOS, Huawei VRP, Eltex ESR / MES) проверяются
так же, как серверы по учётной записи:

1. **Инвентаризация.** По учётке ``netssh`` сканер входит в CLI устройства и
   выполняет только команды просмотра версии (``show version`` / ``display
   version`` / ``/system resource print``); по учётке ``snmp`` — один GET
   системной группы MIB-2 (sysDescr, sysObjectID, sysName). Платформа
   определяется по приглашению CLI, баннеру SSH и тексту версии (или задана в
   учётке).
2. **Уязвимости.** Версия ОС устройства сопоставляется с NVD (CPE продукта:
   cisco:ios, juniper:junos, mikrotik:routeros…) и БДУ ФСТЭК (название ПО и
   диапазоны версий) — находки VULN с CVE и BDU.
3. **Аудит конфигурации.** По SSH читается текущая конфигурация (``show
   running-config``, ``show configuration | display set``, ``/export terse``,
   ``display current-configuration``) и проверяется правилами
   `modules.netdev.rules` (Telnet/HTTP-управление, SNMP v1/v2c и стандартные
   community, хранение паролей, AAA, тайм-ауты, ACL управления, баннер, syslog,
   NTP…) — находки CONFIG ``NETDEV:<правило>``. Итоги правил — факты для
   профилей соответствия ФСТЭК/CIS.

Безопасность:
- цели — только литеральные IP, уже прошедшие allowlist оркестратора; учётки —
  только выбранные оператором для прогона и подходящие хосту по области;
  на хосте пробуется не больше `MAX_CREDENTIALS_PER_HOST` учёток протокола;
- команды — только фиксированный список просмотра (`netdev.platforms`):
  конфигурационный режим, enable, сохранение и перезагрузка не используются;
- секреты учёток не попадают в журнал, аудит и находки; полная конфигурация
  устройства не сохраняется — в доказательства идут только строки правила,
  с маскированием паролей, хэшей, community и ключей;
- подключения ограничены профилем нагрузки (max_concurrency, интервал).
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from scanner.compliance.facts import record as record_fact
from scanner.core import coverage as cv
from scanner.core import netexec, sshexec
from scanner.core.credentials import (
    PROTOCOL_NETSSH,
    PROTOCOL_SNMP,
    HostCredential,
    credentials_for_host,
)
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    InstalledPackage,
    Severity,
)
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import _Throttle
from scanner.modules.netdev import platforms as pf
from scanner.modules.netdev import rules as rl

log = logging.getLogger(__name__)

MODULE = "netdev_audit"
PKG_MANAGER = "firmware"
OS_ID = "network"

CliOpener = Callable[[str, HostCredential, netexec.NetCliOptions], netexec.NetSession]
SnmpGetter = Callable[[str, HostCredential], dict[str, str]]


@dataclass(slots=True)
class NetdevOptions:
    cli: netexec.NetCliOptions = field(
        default_factory=lambda: netexec.NetCliOptions(ssh=sshexec.SshOptions()))
    snmp: netexec.SnmpOptions = field(default_factory=netexec.SnmpOptions)
    max_parallel_hosts: int = 8
    max_config_bytes: int = 4 * 1024 * 1024


def options_from_env() -> NetdevOptions:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class _S(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="SCANNER_NETDEV_", env_file=".env",
                                          extra="ignore")
        command_timeout_sec: float = 60.0
        snmp_timeout_sec: float = 3.0
        snmp_retries: int = 1

    s = _S()
    ssh = sshexec.options_from_env()
    return NetdevOptions(
        cli=netexec.NetCliOptions(ssh=ssh, command_timeout_sec=s.command_timeout_sec),
        snmp=netexec.SnmpOptions(timeout_sec=s.snmp_timeout_sec,
                                 retries=max(0, min(s.snmp_retries, 3))))


@dataclass(slots=True)
class DeviceResult:
    """Что удалось собрать с устройства."""
    info: pf.DeviceInfo
    credential: HostCredential
    config_text: str | None = None
    rules: list[rl.Evaluated] = field(default_factory=list)
    snmp_v2c: bool = False               # агент ответил на SNMPv2c (community)
    notes: list[str] = field(default_factory=list)


class _Matcher:
    store: object

    def findings_for_firmware(self, host: str, **kw) -> list[Finding]: ...


class NetdevAuditModule(ScanModule):
    name = MODULE

    def __init__(self, options: NetdevOptions | None = None, matcher: _Matcher | None = None,
                 cli_opener: CliOpener | None = None, snmp_getter: SnmpGetter | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.options = options or NetdevOptions()
        self._matcher = matcher
        self._open_cli = cli_opener or netexec.open_cli
        self._snmp_get = snmp_getter or (
            lambda host, cred: netexec.snmp_get(host, cred, opts=self.options.snmp))
        self._sleep = sleep

    # ---------- сбор по SSH ----------
    def _collect_cli(self, ctx: ScanContext, host: str, cred: HostCredential
                     ) -> DeviceResult:
        """Вход в CLI, определение платформы, версия и конфигурация.

        Исключения sshexec/netexec пробрасываются вызывающему (_collect)."""
        opts = self.options.cli
        session = self._open_cli(host, cred, opts)
        try:
            hint = cred.options.get("platform") or "auto"
            platform = hint if hint in pf.PLATFORMS else pf.detect_by_prompt(
                session.prompt, session.banner)
            probe = ""
            if platform is None:
                # Cisco-подобный CLI: различаем по show version (до отключения
                # пейджинга — «--More--» пролистывается пробелом).
                probe = session.run("show version", opts.command_timeout_sec)
                platform = pf.detect(probe)
            if platform is None:
                probe = probe or session.run("display version", opts.command_timeout_sec)
                platform = pf.detect(probe)
            if platform is None:
                info = pf.DeviceInfo(source="ssh")
                info.raw_descr = (probe or "").strip().split("\n")[0][:200] or None
                return DeviceResult(info, cred, notes=[
                    ("платформа устройства не распознана — проверены только вход и "
                    "версия; укажите платформу в учётной записи")])
            p = pf.PLATFORMS[platform]
            for cmd in p.setup:
                session.run(cmd, opts.command_timeout_sec)
            version_text = "\n".join(session.run(cmd, opts.command_timeout_sec)
                                     for cmd in p.version_cmds)
            info = pf.parse_version(platform, version_text)
            info.source = "ssh"
            config_cmd = p.config_cmd
            if platform == "routeros" and (info.version or "").startswith("6."):
                config_cmd = "/export hide-sensitive terse"   # v6 иначе выгружает пароли
            config = session.run(config_cmd, opts.command_timeout_sec) if config_cmd else ""
        finally:
            session.close()
        res = DeviceResult(info, cred)
        if config and len(config) <= self.options.max_config_bytes:
            res.config_text = config
            res.rules = rl.evaluate(p.family, config)
            if not res.rules or _looks_denied(config):
                res.notes.append("конфигурация не прочитана: у учётной записи нет прав на "
                                 f"«{config_cmd}» (нужен уровень доступа только для просмотра "
                                 "конфигурации)")
                res.rules = []
        elif config:
            res.notes.append("конфигурация больше лимита — аудит конфигурации пропущен")
        return res

    # ---------- сбор по SNMP ----------
    def _collect_snmp(self, host: str, cred: HostCredential) -> DeviceResult:
        values = self._snmp_get(host, cred)
        descr = values.get(netexec.OID_SYS_DESCR, "")
        platform = pf.detect(descr)
        if platform is None and values.get(netexec.OID_MIKROTIK_VERSION):
            platform = "routeros"
        if platform:
            info = pf.parse_version(platform, descr)
        else:
            info = pf.DeviceInfo()
        if platform == "routeros" and values.get(netexec.OID_MIKROTIK_VERSION):
            info.version = values[netexec.OID_MIKROTIK_VERSION].split()[0]
        info.source = "snmp"
        info.hostname = info.hostname or values.get(netexec.OID_SYS_NAME) or None
        info.raw_descr = " ".join(descr.split())[:300] or None
        return DeviceResult(info, cred,
                            snmp_v2c=(cred.options or {}).get("snmp_version") == "2c")

    # ---------- хост ----------
    def _collect(self, ctx: ScanContext, throttle: _Throttle, host: str,
                 creds: list[HostCredential]) -> tuple[DeviceResult | None, list[Finding]]:
        """Сначала SSH (версия + конфигурация), если не вышло — SNMP (версия)."""
        notes: list[Finding] = []
        ssh_creds = [c for c in creds if c.protocol == PROTOCOL_NETSSH]
        snmp_creds = [c for c in creds if c.protocol == PROTOCOL_SNMP]
        best: DeviceResult | None = None
        fatal = False
        for cred in ssh_creds:
            info = cred.describe()
            throttle.wait()
            ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                             result="started", details=info)
            try:
                best = self._collect_cli(ctx, host, cred)
            except sshexec.AuthFailed:
                ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                                 result="auth_failed", details=info)
                notes.append(self._info(host, "INFO:netdev-auth-failed",
                                        "Вход в CLI устройства отклонён",
                                        f"учётка «{cred.name}» ({cred.username}@{host}:"
                                        f"{cred.port}): логин или пароль/ключ отклонены"))
                ctx.coverage.mark(host, MODULE, cv.ERROR,
                                  f"учётка «{cred.name}» отклонена устройством")
                continue
            except sshexec.HostKeyMismatch as e:
                ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                                 result="host_key_mismatch",
                                 details={**info, "error": str(e)[:300]})
                ctx.coverage.mark(host, MODULE, cv.ERROR, f"ключ SSH: {e}"[:300], force=True)
                notes.append(self._info(host, "INFO:netdev-host-key",
                                        "Ключ SSH устройства не прошёл проверку", str(e)))
                fatal = True
                break
            except (sshexec.Unreachable, sshexec.CommandTimeout) as e:
                ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                                 result="unreachable", details={**info, "error": str(e)[:300]})
                ctx.coverage.mark(host, MODULE, sshexec.failure_status(e), str(e)[:300],
                                  force=True)
                notes.append(self._info(host, "INFO:netdev-unreachable",
                                        "Устройство недоступно по SSH", str(e)[:500]))
                break                           # тот же порт — следующая учётка не поможет
            except (sshexec.SshError, netexec.NetError, ValueError) as e:
                ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                                 result="error", details={**info, "error": str(e)[:300]})
                ctx.coverage.mark(host, MODULE, cv.ERROR, str(e)[:300])
                notes.append(self._info(host, "INFO:netdev-error",
                                        "Опрос устройства по SSH не выполнен", str(e)[:500]))
                continue
            ctx.audit.record(subject="scanner", action="netdev_ssh", target=host,
                             result="ok", details={**info, "platform": best.info.platform,
                                                   "version": best.info.version,
                                                   "rules": len(best.rules)})
            break
        if best is None and not fatal:
            for cred in snmp_creds:
                info = cred.describe()
                throttle.wait()
                try:
                    best = self._collect_snmp(host, cred)
                except netexec.SnmpAuthFailed as e:
                    ctx.audit.record(subject="scanner", action="netdev_snmp", target=host,
                                     result="auth_failed", details=info)
                    notes.append(self._info(host, "INFO:netdev-auth-failed",
                                            "SNMPv3: учётная запись отклонена", str(e)))
                    ctx.coverage.mark(host, MODULE, cv.ERROR, str(e)[:300])
                    continue
                except netexec.SnmpTimeout as e:
                    ctx.audit.record(subject="scanner", action="netdev_snmp", target=host,
                                     result="timeout", details=info)
                    notes.append(self._info(host, "INFO:netdev-unreachable",
                                            "Агент SNMP не ответил", str(e)))
                    ctx.coverage.mark(host, MODULE, cv.TIMEOUT, str(e)[:300])
                    continue
                except netexec.NetError as e:
                    ctx.audit.record(subject="scanner", action="netdev_snmp", target=host,
                                     result="error", details={**info, "error": str(e)[:300]})
                    notes.append(self._info(host, "INFO:netdev-error",
                                            "Опрос устройства по SNMP не выполнен", str(e)))
                    ctx.coverage.mark(host, MODULE, cv.ERROR, str(e)[:300])
                    continue
                ctx.audit.record(subject="scanner", action="netdev_snmp", target=host,
                                 result="ok", details={**info, "platform": best.info.platform,
                                                       "version": best.info.version})
                break
        if best is not None:
            ctx.coverage.mark(host, MODULE, cv.COMPLETED, force=True)
            return best, []          # вход удался — заметки об отказах не нужны
        return None, notes

    # ---------- находки ----------
    @staticmethod
    def _info(host: str, vuln_id: str, title: str, evidence: str | None) -> Finding:
        return Finding(module=MODULE, host=host, finding_type=FindingType.INFO,
                       title=title, severity=Severity.INFO, vuln_id=vuln_id,
                       evidence=evidence)

    def _rule_findings(self, host: str, r: DeviceResult) -> list[Finding]:
        p = pf.PLATFORMS.get(r.info.platform or "")
        out: list[Finding] = []
        for ev in r.rules:
            if ev.result.status != rl.FAIL:
                continue
            rule = ev.rule
            rem = rule.remediation.get(p.family if p else "", "")
            lines = [f"Устройство: {r.info.label}"]
            if ev.result.note:
                lines.append(f"Нарушение: {ev.result.note}")
            if ev.result.evidence:
                lines.append("Строки конфигурации (секреты скрыты):")
                lines += [f"  {x}" for x in ev.result.evidence]
            if rule.refs:
                lines.append("Ссылки: " + "; ".join(rule.refs))
            out.append(Finding(
                module=MODULE, host=host, finding_type=FindingType.CONFIG,
                title=rule.title, severity=rule.severity, vuln_id=rule.vuln_id,
                evidence="\n".join(lines),
                remediation=(f"{rule.description} {('Исправление: ' + rem) if rem else ''}"
                             ).strip()))
        if r.snmp_v2c and not any(f.vuln_id == "NETDEV:snmp_v12" for f in out):
            rule = rl.RULES_BY_ID["snmp_v12"]
            out.append(Finding(
                module=MODULE, host=host, finding_type=FindingType.CONFIG,
                title=rule.title, severity=rule.severity, vuln_id=rule.vuln_id,
                evidence=(f"Устройство: {r.info.label}\nАгент SNMP ответил на запрос "
                          f"SNMPv2c (учётка «{r.credential.name}»)."),
                remediation=f"{rule.description} Перейдите на SNMPv3 (authPriv) и "
                            "удалите community v1/v2c."))
        return out

    def _vuln_findings(self, ctx: ScanContext, host: str, r: DeviceResult,
                       matcher: _Matcher | None) -> list[Finding]:
        info = r.info
        if matcher is None or not info.version or not info.platform:
            return []
        p = pf.PLATFORMS[info.platform]
        try:
            found = matcher.findings_for_firmware(
                host, product=info.os_name or p.os_name,
                versions=[info.version, *info.extra_versions], cpe=pf.cpe_for(info),
                bdu_names=pf.bdu_names(info), module=MODULE,
                source="по SSH" if info.source == "ssh" else "по SNMP (sysDescr)")
        except Exception as e:  # noqa: BLE001 — справочник недоступен: инвентарь важнее
            ctx.audit.record(subject="scanner", action="netdev_match", target=host,
                             result="error", details=f"{type(e).__name__}: {e}"[:300])
            return []
        for f in found:
            # Рекомендацию даёт отчёт (БДУ/NVD); здесь — где искать исправленную версию.
            if p.vendor_doc:
                f.evidence = (f.evidence or "") + f"\nБюллетени вендора: {p.vendor_doc}"
            f.source = "vendor_version"
            f.confidence = "high" if info.source == "ssh" else "medium"
        ctx.audit.record(subject="scanner", action="netdev_match", target=host,
                         result="ok", details={"platform": info.platform,
                                               "version": info.version,
                                               "findings": len(found)})
        return found

    def _summary(self, host: str, r: DeviceResult, vulns: int) -> Finding:
        info = r.info
        lines = [f"Устройство: {info.label}"]
        if info.hostname:
            lines.append(f"имя: {info.hostname}")
        if info.serial:
            lines.append(f"серийный номер: {info.serial}")
        lines.append("источник: " + ("CLI по SSH" if info.source == "ssh" else
                                     "SNMP (sysDescr)"))
        if info.raw_descr and not info.platform:
            lines.append(f"описание: {info.raw_descr}")
        if r.rules:
            failed = sum(e.result.status == rl.FAIL for e in r.rules)
            passed = sum(e.result.status == rl.PASS for e in r.rules)
            lines.append(f"правил конфигурации: выполнено {passed}, нарушено {failed}, "
                         f"не применимо {len(r.rules) - failed - passed}")
        elif info.source == "snmp":
            lines.append("аудит конфигурации: нет (по SNMP конфигурация не читается — "
                         "добавьте учётку SSH сетевого устройства)")
        lines.append(f"уязвимостей по версии ОС: {vulns}" if info.version else
                     "версия ОС не определена — уязвимости по версии не проверены")
        lines += r.notes
        lines.append(f"учётная запись: «{r.credential.name}» ({r.credential.username}, "
                     f"{'SSH' if r.credential.protocol == PROTOCOL_NETSSH else 'SNMP'})")
        title = f"Сетевое устройство: {info.label}"
        return self._info(host, "INFO:netdev-inventory", title, "\n".join(lines))

    @staticmethod
    def _inventory(host: str, r: DeviceResult) -> HostInventory:
        info = r.info
        pkgs = []
        if info.os_name and info.version:
            pkgs.append(InstalledPackage(name=info.os_name, version=info.version,
                                         manager=PKG_MANAGER))
        return HostInventory(host=host, os_id=OS_ID, os_name=info.label,
                             os_version=info.version, hostname=info.hostname,
                             packages=pkgs, credential_id=r.credential.id)

    @staticmethod
    def _facts(ctx: ScanContext, host: str, r: DeviceResult) -> None:
        rules = {e.rule.id: e.result.status for e in r.rules}
        if r.snmp_v2c and rules.get("snmp_v12") != rl.FAIL:
            rules["snmp_v12"] = rl.FAIL
        record_fact(ctx.compliance_facts, host, "netdev",
                    {"platform": r.info.platform, "version": r.info.version,
                     "source": r.info.source, "rules": rules})

    # ---------- прогон ----------
    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts = []
        for t in ctx.targets:
            try:
                hosts.append(str(ipaddress.ip_address(t.strip())))
            except ValueError:
                ctx.audit.record(subject="scanner", action="netdev_deny", target=t,
                                 result="not_an_ip_literal")
        return hosts

    def run(self, ctx: ScanContext) -> list[Finding]:
        from concurrent.futures import ThreadPoolExecutor

        alive = ctx.alive_hosts()
        has_netdev = any(c.protocol in (PROTOCOL_NETSSH, PROTOCOL_SNMP)
                         for c in ctx.credentials)
        jobs: list[tuple[str, list[HostCredential]]] = []
        for host in self._hosts(ctx):
            ssh = credentials_for_host(host, ctx.credentials, protocol=PROTOCOL_NETSSH)
            snmp = credentials_for_host(host, ctx.credentials, protocol=PROTOCOL_SNMP)
            if alive is not None and host not in alive:
                ssh = []        # discovery не нашёл TCP-портов: SSH не пробуем
                if not snmp:    # SNMP — UDP, discovery его не видит: пробуем
                    ctx.coverage.mark(host, MODULE, cv.UNREACHABLE,
                                      "хост не обнаружен (нет открытых портов)")
                    continue
            if not ssh and not snmp:
                fam = ctx.host_family(host)
                if fam == "network" or (fam is None and has_netdev):
                    ctx.coverage.mark(host, MODULE, cv.NO_CREDENTIALS,
                                      "нет учётки сетевого оборудования для устройства")
                else:
                    ctx.coverage.mark(host, MODULE, cv.NOT_APPLICABLE,
                                      "не сетевое устройство" if fam else
                                      "в прогоне нет учёток сетевого оборудования")
                ctx.audit.record(subject="scanner", action="netdev_skip", target=host,
                                 result="no_netdev_credentials")
                continue
            jobs.append((host, ssh + snmp))
        if not jobs:
            return []

        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netdev") as pool:
            collected = list(pool.map(lambda j: (j[0], self._collect(ctx, throttle, *j)),
                                      jobs))

        matcher = self._matcher
        findings: list[Finding] = []
        for host, (res, notes) in collected:
            findings.extend(notes)
            if res is None:
                continue
            ctx.inventory[host] = self._inventory(host, res)
            vulns = self._vuln_findings(ctx, host, res, matcher)
            findings.append(self._summary(host, res, len(vulns)))
            findings.extend(self._rule_findings(host, res))
            findings.extend(vulns)
            self._facts(ctx, host, res)
        return findings


def _looks_denied(text: str) -> bool:
    """Вывод вместо конфигурации — отказ в доступе или неизвестная команда."""
    head = text.strip()[:300].lower()
    if len(text.strip()) < 40:
        return True
    return any(k in head for k in ("% invalid input", "% authorization failed",
                                   "permission denied", "error: unknown command",
                                   "unrecognized command", "% bad command", "not authorized",
                                   "access denied", "bad command name"))
