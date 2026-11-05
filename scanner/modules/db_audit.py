"""Модуль: аудит СУБД по учётной записи только на чтение (db_audit).

Сканер подключается к СУБД учётной записью договора (протоколы учёток
``postgresql``, ``mysql``, ``mssql``, ``oracle``), выполняет фиксированные
запросы на чтение системных представлений (`db_checks.QUERIES`) и выдаёт:

- версию и редакцию СУБД → уязвимости:
  * PostgreSQL, MySQL, MariaDB, Oracle Database — `VulnMatcher` (NVD по CPE +
    БДУ ФСТЭК по названию ПО и версии);
  * Postgres Pro — БДУ по названиям Postgres Pro и NVD по версии PostgreSQL, на
    которой основана сборка;
  * Microsoft SQL Server — справочник обновлений Microsoft (MSRC): сборка
    экземпляра против ``FixedBuild`` той же ветки обслуживания (GDR/CU), CVE
    связываются с БДУ ФСТЭК;
- окончание поддержки ветки производителем (после него исправлений нет);
- нарушения конфигурации по мотивам CIS Benchmarks (`db_checks.CHECKS`):
  TLS, методы аутентификации, пароли по умолчанию/пустые, опасные функции,
  журналирование и аудит.

Правило, для которого у учётки не хватило прав (или нет данных), получает
статус «не проверено» — в сводке перечисляется, каких прав не хватило; оно не
считается выполненным.

Безопасность (как у auth_inventory / win_inventory):
- цели — только литеральные IP, уже прошедшие allowlist; если в прогоне был
  discovery, подключаемся только к хостам, где он нашёл открытым порт учётки;
- учётки — только учётки СУБД, выбранные оператором для прогона, с областью
  действия, покрывающей хост; не больше `MAX_CREDENTIALS_PER_HOST` на порт;
- сессия только на чтение (см. `core.dbexec`), запросы — константы из кода;
- пароль не попадает в журнал, аудит и находки;
- подключения ограничены профилем нагрузки (max_concurrency, интервал).
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from scanner.compliance.facts import record as record_fact
from scanner.core import coverage as cv
from scanner.core.credentials import (
    DB_PROTOCOLS,
    MAX_CREDENTIALS_PER_HOST,
    PROTOCOL_MSSQL,
    PROTOCOL_MYSQL,
    PROTOCOL_ORACLE,
    PROTOCOL_POSTGRESQL,
    HostCredential,
    credentials_for_host,
)
from scanner.core.dbexec import (
    Connector,
    DbAuthFailed,
    DbDriverMissing,
    DbError,
    DbOptions,
    DbQueryError,
    DbSession,
    DbUnreachable,
    connect,
    is_timeout,
)
from scanner.core.models import Finding, FindingType, Severity
from scanner.feeds.severity import max_severity, severity_from_cvss
from scanner.modules import db_checks as dc
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import _Throttle

log = logging.getLogger(__name__)

MODULE = "db_audit"

PROTOCOL_LABELS = {PROTOCOL_POSTGRESQL: "PostgreSQL", PROTOCOL_MYSQL: "MySQL/MariaDB",
                   PROTOCOL_MSSQL: "MS SQL Server", PROTOCOL_ORACLE: "Oracle"}

# Названия сервисов nmap -> протокол учётки (для «СУБД найдена, учётки нет»).
SERVICE_PROTOCOLS = {"postgresql": PROTOCOL_POSTGRESQL, "mysql": PROTOCOL_MYSQL,
                     "mariadb": PROTOCOL_MYSQL, "ms-sql-s": PROTOCOL_MSSQL,
                     "ms-sql": PROTOCOL_MSSQL, "mssql": PROTOCOL_MSSQL,
                     "oracle-tns": PROTOCOL_ORACLE, "oracle": PROTOCOL_ORACLE}

_MSRC_SEVERITY = {"critical": Severity.CRITICAL, "important": Severity.HIGH,
                  "moderate": Severity.MEDIUM, "low": Severity.LOW}

# Продукт -> (название ПО, CPE для NVD, названия ПО в БДУ).
_VULN_SOFTWARE: dict[str, tuple[str, str | None, tuple[str, ...]]] = {
    dc.POSTGRESQL: ("PostgreSQL", "cpe:/a:postgresql:postgresql", ("PostgreSQL",)),
    dc.POSTGRESPRO: ("Postgres Pro", None,
                     ("Postgres Pro", "Postgres Pro Standard", "Postgres Pro Enterprise",
                      "Postgres Pro Certified", "Postgres Pro Enterprise Certified")),
    dc.MYSQL: ("MySQL", "cpe:/a:oracle:mysql", ("MySQL", "MySQL Server")),
    dc.MARIADB: ("MariaDB", "cpe:/a:mariadb:mariadb", ("MariaDB", "MariaDB Server")),
    dc.ORACLE: ("Oracle Database", "cpe:/a:oracle:database_server",
                ("Oracle Database", "Oracle Database Server")),
}

VERSION_NOTE = ("Версия получена от самой СУБД. Сборки дистрибутива и отечественные "
                "сборки могут содержать перенесённые исправления — сверьтесь с "
                "бюллетенем поставщика сборки.")


@dataclass(slots=True)
class DbAuditOptions:
    db: DbOptions = field(default_factory=DbOptions)
    max_parallel_hosts: int = 8          # верхняя граница; реальная — min с профилем


@dataclass(slots=True)
class _Job:
    host: str
    protocol: str
    port: int
    creds: list[HostCredential]


@dataclass(slots=True)
class _Collected:
    job: _Job
    facts: dc.DbFacts | None = None
    cred: HostCredential | None = None
    notes: list[Finding] = field(default_factory=list)
    gap: tuple[str, str] | None = None      # (статус покрытия, причина) при неудаче


class DbAuditModule(ScanModule):
    name = MODULE

    def __init__(self, options: DbAuditOptions | None = None,
                 matcher: object | None = None, connector: Connector | None = None,
                 msrc_store: object | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 today: Callable[[], date] = date.today):
        self.options = options or DbAuditOptions()
        self._matcher = matcher
        self._connect = connector or connect
        self._msrc_store = msrc_store
        self._sleep = sleep
        self._today = today

    # ---------- выбор целей ----------
    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts = []
        for t in ctx.targets:
            try:
                hosts.append(str(ipaddress.ip_address(t.strip())))
            except ValueError:
                ctx.audit.record(subject="scanner", action="db_audit_deny", target=t,
                                 result="not_an_ip_literal")
        return list(dict.fromkeys(hosts))

    def _jobs(self, ctx: ScanContext) -> list[_Job]:
        discovered = "discovery" in ctx.completed and ctx.services is not None
        open_ports: dict[str, set[int]] = {}
        db_services: dict[str, dict[int, str]] = {}
        for s in ctx.services or []:
            open_ports.setdefault(s.host, set()).add(s.port)
            proto = SERVICE_PROTOCOLS.get((s.service or "").lower())
            if proto:
                db_services.setdefault(s.host, {})[s.port] = proto
        jobs: list[_Job] = []
        for host in self._hosts(ctx):
            planned: list[_Job] = []
            for proto in DB_PROTOCOLS:
                creds = credentials_for_host(host, ctx.credentials, limit=len(
                    ctx.credentials) or 1, protocol=proto)
                by_port: dict[int, list[HostCredential]] = {}
                for c in creds:
                    by_port.setdefault(c.port, []).append(c)
                for port, items in by_port.items():
                    planned.append(_Job(host, proto, port,
                                        items[:MAX_CREDENTIALS_PER_HOST]))
            if discovered:
                alive = open_ports.get(host)
                if not alive:
                    ctx.coverage.mark(host, MODULE, cv.UNREACHABLE,
                                      "хост не обнаружен (нет открытых портов)")
                    ctx.audit.record(subject="scanner", action="db_audit_skip",
                                     target=host, result="host_not_discovered")
                    continue
                kept = [j for j in planned if j.port in alive]
                for j in planned:
                    if j.port not in alive:
                        ctx.audit.record(subject="scanner", action="db_audit_skip",
                                         target=f"{host}:{j.port}",
                                         result="port_not_open",
                                         details={"protocol": j.protocol})
                covered = {(j.protocol, j.port) for j in kept}
                missing = [(port, proto) for port, proto in
                           (db_services.get(host) or {}).items()
                           if (proto, port) not in covered]
                if missing:
                    what = ", ".join(f"{PROTOCOL_LABELS[p]} :{port}"
                                     for port, p in sorted(missing))
                    ctx.coverage.mark(host, MODULE, cv.NO_CREDENTIALS,
                                      f"найдена СУБД ({what}), но учётки СУБД для неё нет")
                    ctx.audit.record(subject="scanner", action="db_audit_skip",
                                     target=host, result="no_db_credentials",
                                     details={"services": what})
                if not kept and not missing:
                    ctx.coverage.mark(host, MODULE, cv.NOT_APPLICABLE,
                                      "порты СУБД из учёток на хосте закрыты"
                                      if planned else "СУБД на хосте не найдена")
                planned = kept
            elif not planned:
                ctx.coverage.mark(host, MODULE, cv.NOT_APPLICABLE,
                                  "нет учётки СУБД для хоста")
            jobs.extend(planned)
        return jobs

    # ---------- сбор ----------
    def _collect(self, ctx: ScanContext, throttle: _Throttle, job: _Job) -> _Collected:
        out = _Collected(job)
        target = f"{job.host}:{job.port}"
        label = PROTOCOL_LABELS[job.protocol]
        for cred in job.creds:
            info = cred.describe()
            throttle.wait()
            ctx.audit.record(subject="scanner", action="db_audit_connect", target=target,
                             result="started", details=info)
            try:
                session = self._connect(job.host, cred, self.options.db)
            except DbAuthFailed as e:
                out.gap = (cv.ERROR, f"{label}: учётка «{cred.name}» отклонена")
                ctx.audit.record(subject="scanner", action="db_audit_connect",
                                 target=target, result="auth_failed",
                                 details={**info, "error": str(e)[:300]})
                out.notes.append(self._info(
                    job, "INFO:db-audit-auth-failed", f"Вход в {label} отклонён",
                    f"учётка «{cred.name}» ({cred.username}@{target}): {e}"))
                continue
            except DbDriverMissing as e:
                out.gap = (cv.ERROR, str(e)[:300])
                ctx.audit.record(subject="scanner", action="db_audit_connect",
                                 target=target, result="driver_missing",
                                 details={**info, "error": str(e)[:300]})
                out.notes.append(self._info(job, "INFO:db-audit-error",
                                            f"Аудит {label} не выполнен", str(e)))
                return out
            except DbUnreachable as e:
                out.gap = (cv.TIMEOUT if is_timeout(e) else cv.UNREACHABLE,
                           f"{label} :{job.port}: {e}"[:300])
                ctx.audit.record(subject="scanner", action="db_audit_connect",
                                 target=target, result="unreachable",
                                 details={**info, "error": str(e)[:300]})
                out.notes.append(self._info(job, "INFO:db-audit-unreachable",
                                            f"{label} недоступна", f"{target}: {e}"))
                return out
            except DbError as e:
                out.gap = (cv.ERROR, f"{label}: {e}"[:300])
                ctx.audit.record(subject="scanner", action="db_audit_connect",
                                 target=target, result="error",
                                 details={**info, "error": str(e)[:300]})
                out.notes.append(self._info(job, "INFO:db-audit-error",
                                            f"Аудит {label} не выполнен", str(e)[:500]))
                continue
            try:
                facts = self._run_queries(session, job.protocol)
            finally:
                session.close()
            out.facts, out.cred, out.notes, out.gap = facts, cred, [], None
            ctx.audit.record(subject="scanner", action="db_audit_query", target=target,
                             result="ok" if facts.has("version") else "no_version",
                             details={**info, "queries": sorted(facts.rows),
                                      "unavailable": sorted(facts.unavailable)})
            return out
        return out

    @staticmethod
    def _run_queries(session: DbSession, protocol: str) -> dc.DbFacts:
        facts = dc.DbFacts(protocol)
        for name, sql in dc.QUERIES[protocol].items():
            try:
                facts.rows[name] = session.query(sql)
            except DbQueryError as e:
                facts.unavailable[name] = str(e)[:300]
        return facts

    # ---------- находки ----------
    @staticmethod
    def _info(job: _Job, vuln_id: str, title: str, evidence: str | None) -> Finding:
        return Finding(module=MODULE, host=job.host, port=job.port,
                       finding_type=FindingType.INFO, title=title, severity=Severity.INFO,
                       vuln_id=vuln_id, evidence=evidence)

    def _config_findings(self, job: _Job, product: dc.DbProduct | None,
                         results: list[tuple[dc.DbCheck, dc.CheckResult]]) -> list[Finding]:
        name = product.label if product else PROTOCOL_LABELS[job.protocol]
        out = []
        for check, res in results:
            if res.status != dc.FAIL:
                continue
            out.append(Finding(
                module=MODULE, host=job.host, port=job.port,
                finding_type=FindingType.CONFIG, title=check.title,
                severity=check.severity, vuln_id=check.id,
                evidence=f"{name}, порт {job.port}\n{res.evidence}".strip(),
                remediation=f"{check.remediation}\nОснование: {check.reference}.",
                source="config", confidence="high"))
        return out

    def _eol_finding(self, job: _Job, product: dc.DbProduct) -> Finding | None:
        end = dc.end_of_support(product)
        if end is None or end > self._today():
            return None
        return Finding(
            module=MODULE, host=job.host, port=job.port, finding_type=FindingType.VULN,
            title=f"{product.label}: ветка не поддерживается производителем с "
                  f"{end:%d.%m.%Y}", severity=Severity.HIGH, vuln_id="DB-EOL",
            evidence=f"Версия: {product.raw or product.version}\nОкончание поддержки: "
                     f"{end:%d.%m.%Y}",
            remediation="Обновите СУБД до поддерживаемой ветки: для неподдерживаемой "
                        "версии исправления безопасности не выпускаются.",
            source="authenticated_package", confidence="high")

    def _vuln_findings(self, ctx: ScanContext, job: _Job, product: dc.DbProduct,
                       matcher: object | None, store: object | None
                       ) -> tuple[list[Finding], str]:
        """Уязвимости версии СУБД и строка о результате для сводки."""
        if product.kind == dc.MSSQL:
            return self._mssql_findings(ctx, job, product, store)
        if matcher is None:
            return [], "справочники уязвимостей не подключены"
        name, cpe, bdu_names = _VULN_SOFTWARE[product.kind]
        calls = [(name, product.version, cpe, bdu_names)]
        if product.kind == dc.POSTGRESPRO and product.upstream:
            calls.append(("PostgreSQL", product.upstream, _VULN_SOFTWARE[dc.POSTGRESQL][1],
                          ()))
        found: dict[str, Finding] = {}
        for prod, ver, cp, names in calls:
            try:
                items = matcher.findings_for_package(           # type: ignore[attr-defined]
                    job.host, product=prod, version=ver, cpe=cp, bdu_names=names,
                    packages=[product.label], use_nvd=cp is not None, module=MODULE)
            except Exception as e:  # noqa: BLE001 — справочник недоступен: аудит важнее
                ctx.audit.record(subject="scanner", action="db_audit_match",
                                 target=f"{job.host}:{job.port}", result="error",
                                 details={"product": prod,
                                          "error": f"{type(e).__name__}: {e}"[:300]})
                continue
            for f in items:
                f.port = job.port
                f.evidence = self._vuln_evidence(job, product, prod, ver, f.evidence)
                f.source, f.confidence = "authenticated_package", "medium"
                found.setdefault(f.vuln_id or "", f)
        ctx.audit.record(subject="scanner", action="db_audit_match",
                         target=f"{job.host}:{job.port}", result="ok",
                         details={"product": product.label, "findings": len(found)})
        return list(found.values()), f"уязвимостей версии (CVE/БДУ): {len(found)}"

    @staticmethod
    def _vuln_evidence(job: _Job, product: dc.DbProduct, prod: str, ver: str,
                       evidence: str | None) -> str:
        from scanner.feeds.matcher import BACKPORT_CAVEAT
        lines = [ln for ln in (evidence or "").splitlines()[1:]
                 if ln and ln != BACKPORT_CAVEAT]
        head = f"{product.label} на порту {job.port}"
        if product.raw and product.raw != product.version:
            head += f" (сообщает СУБД: {product.raw[:200]})"
        if prod != dc.PRODUCT_LABELS.get(product.kind):
            head += f"\nСопоставлено как {prod} {ver} (основа сборки)"
        return "\n".join([head, *lines, VERSION_NOTE])

    def _mssql_findings(self, ctx: ScanContext, job: _Job, product: dc.DbProduct,
                        store: object | None) -> tuple[list[Finding], str]:
        from scanner.feeds.msrc import CATALOG_URL, GUIDE_URL, assess_sql
        if store is None:
            ctx.run_notes.append({"kind": "msrc_missing", "host": job.host,
                                  "message": "справочник MSRC не загружен — уязвимости "
                                             "SQL Server не проверены"})
            return [], ("уязвимости SQL Server: справочник MSRC не загружен "
                        "(scanner feeds sync-msrc)")
        year = dc.mssql_year(product.version)
        try:
            a = assess_sql(product.version, year, store)
        except Exception as e:  # noqa: BLE001
            ctx.audit.record(subject="scanner", action="db_audit_msrc",
                             target=f"{job.host}:{job.port}", result="error",
                             details=f"{type(e).__name__}: {e}"[:300])
            return [], "уязвимости SQL Server: ошибка справочника MSRC"
        ctx.audit.record(subject="scanner", action="db_audit_msrc",
                         target=f"{job.host}:{job.port}",
                         result="no_data" if a.no_data else "ok",
                         details={"product": a.product, "gaps": len(a.gaps),
                                  "fixed": a.fixed, "reason": a.reason})
        if a.no_data:
            return [], f"уязвимости SQL Server: {a.reason}"
        out = []
        for g in a.gaps:
            msrc_sev = _MSRC_SEVERITY.get((g.severity or "").lower())
            cvss_sev = severity_from_cvss(g.cvss)
            sev = (max_severity(msrc_sev, cvss_sev) if (msrc_sev or cvss_sev)
                   else Severity.MEDIUM)
            rem = []
            if g.recommended_kb:
                rem.append(f"Установите обновление безопасности SQL Server KB"
                           f"{g.recommended_kb} (или более позднее накопительное "
                           f"обновление той же ветки).")
                rem.append(CATALOG_URL.format(kb=g.recommended_kb))
            if g.fixed_build:
                rem.append(f"Сборка с исправлением: не ниже {g.fixed_build}.")
            rem.append(GUIDE_URL.format(cve=g.cve_id))
            f = Finding(module=MODULE, host=job.host, port=job.port,
                        finding_type=FindingType.VULN,
                        title=g.title or f"{g.cve_id}: нет обновления SQL Server",
                        severity=sev, vuln_id=g.cve_id, cve_ids=[g.cve_id], cvss=g.cvss,
                        remediation="\n".join(rem), source="vendor_advisory",
                        confidence="high")
            if self._matcher is not None:
                try:
                    self._matcher.enrich(f)                  # type: ignore[attr-defined]
                except Exception:
                    log.warning("БДУ: не удалось обогатить находку %s", f.vuln_id,
                                exc_info=True)
            f.evidence = "\n".join([
                f"{product.label} ({product.raw}) на порту {job.port}",
                f"Продукт MSRC: {a.product}",
                "KB с исправлением: " + ", ".join(f"KB{k}" for k in g.fix_kbs),
                f"Бюллетень: {g.release}"])
            out.append(f)
        return out, (f"отсутствующих обновлений SQL Server (CVE): {len(out)}; "
                     f"закрыто сборкой: {a.fixed}")

    def _summary(self, job: _Job, facts: dc.DbFacts, product: dc.DbProduct | None,
                 cred: HostCredential | None,
                 results: list[tuple[dc.DbCheck, dc.CheckResult]], vuln_line: str
                 ) -> Finding:
        failed = sum(1 for _, r in results if r.status == dc.FAIL)
        passed = sum(1 for _, r in results if r.status == dc.PASS)
        unknown = [c for c, r in results if r.status == dc.UNKNOWN]
        lines = [f"СУБД: {product.label if product else 'версия не определена'}"]
        if product and product.raw:
            lines.append(f"сообщает СУБД: {product.raw[:300]}")
        if product and product.kind == dc.POSTGRESPRO and product.upstream:
            lines.append(f"основана на PostgreSQL {product.upstream}")
        lines.append(vuln_line)
        lines.append(f"правила конфигурации: нарушено {failed}, выполнено {passed}, "
                     f"не проверено {len(unknown)}")
        if unknown:
            lines.append("не проверено: " + ", ".join(c.id for c in unknown))
        grants = dc.QUERY_GRANTS.get(job.protocol, {})
        missing = [q for q in facts.unavailable if q not in dc.OPTIONAL_QUERIES]
        for q in missing:
            hint = grants.get(q)
            lines.append(f"нет данных «{q}»" + (f" — нужно право: {hint}" if hint else "")
                         + f" ({facts.unavailable[q][:160]})")
        if cred is not None:
            lines.append(f"учётная запись: «{cred.name}» ({cred.username}, "
                         f"{PROTOCOL_LABELS[job.protocol]}"
                         + (f", база {cred.db_name}" if cred.db_name else "") + ")")
        title = (f"Аудит СУБД: {product.label if product else PROTOCOL_LABELS[job.protocol]}"
                 f", порт {job.port} — нарушений конфигурации {failed}")
        return self._info(job, "INFO:db-audit", title, "\n".join(lines))

    # ---------- запуск ----------
    def run(self, ctx: ScanContext) -> list[Finding]:
        from concurrent.futures import ThreadPoolExecutor

        jobs = self._jobs(ctx)
        if not jobs:
            return []
        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="db-audit") as pool:
            collected = list(pool.map(lambda j: self._collect(ctx, throttle, j), jobs))

        matcher = self._run_matcher()
        store = self._resolve_msrc_store() if any(
            c.facts is not None and c.job.protocol == PROTOCOL_MSSQL
            for c in collected) else None
        findings: list[Finding] = []
        for c in collected:
            findings.extend(c.notes)
            if c.facts is None:
                if c.gap is not None:
                    ctx.coverage.mark(c.job.host, MODULE, *c.gap)
                continue
            job, facts = c.job, c.facts
            product = dc.detect_product(facts)
            results = dc.evaluate(facts)
            if product is not None:
                vulns, vuln_line = self._vuln_findings(ctx, job, product, matcher, store)
                eol = self._eol_finding(job, product)
                if eol is not None:
                    vulns.insert(0, eol)
            else:
                vulns, vuln_line = [], ("версия СУБД не прочитана — уязвимости версии не "
                                        "проверены")
            findings.append(self._summary(job, facts, product, c.cred, results, vuln_line))
            findings.extend(self._config_findings(job, product, results))
            findings.extend(vulns)
            if product is None:
                ctx.coverage.mark(job.host, MODULE, cv.ERROR,
                                  f"{PROTOCOL_LABELS[job.protocol]}: версия не прочитана")
            else:
                ctx.coverage.mark(job.host, MODULE, cv.COMPLETED)
            record_fact(ctx.compliance_facts, job.host, f"dbms:{job.port}", {
                "product": product.kind if product else job.protocol,
                "version": product.version if product else None,
                "failed": [ch.id for ch, r in results if r.status == dc.FAIL],
                "passed": [ch.id for ch, r in results if r.status == dc.PASS]})
        return findings

    def _resolve_msrc_store(self) -> object | None:
        if self._msrc_store is not None:
            return self._msrc_store
        engine = getattr(getattr(self._matcher, "store", None), "engine", None)
        if engine is None:
            return None
        from scanner.feeds.msrc import MsrcStore
        try:
            s = MsrcStore(engine)
            return s if s.count() else None
        except Exception:
            log.warning("MSRC: справочник недоступен — SQL Server без оценки обновлений",
                        exc_info=True)
            return None

    def _run_matcher(self) -> object | None:
        if self._matcher is None:
            return None
        from scanner.feeds.matcher import VulnMatcher
        from scanner.feeds.store import CachingReferenceStore
        m = self._matcher
        if not isinstance(m, VulnMatcher):
            return m
        return VulnMatcher(CachingReferenceStore(m.store),  # type: ignore[arg-type]
                           bdu_product_match=m.bdu_product_match,
                           bdu_software_aliases=m.bdu_software_aliases)
