"""Аудит СУБД (modules/db_audit.py, modules/db_checks.py, core/dbexec.py).

Подключение к СУБД заменяется фейковой сессией (FakeDb): модуль выполняет свои
фиксированные запросы, а сессия отвечает заранее заданными строками по имени
запроса (или ошибкой «нет прав»). Так проверяются определение продукта и версии,
правила конфигурации, сопоставление с CVE/БДУ/MSRC, покрытие и гарантии
безопасности (только учётки СУБД, только SELECT/SHOW, пароль не утекает) без
настоящих СУБД.
"""
from __future__ import annotations

import re
from datetime import date

import pytest

from scanner.core import coverage as cv
from scanner.core.credentials import (
    PROTOCOL_MSSQL,
    PROTOCOL_MYSQL,
    PROTOCOL_ORACLE,
    PROTOCOL_POSTGRESQL,
    PROTOCOL_SSH,
    CredentialError,
    HostCredential,
    validate_db_name,
)
from scanner.core.dbexec import DbAuthFailed, DbQueryError, DbUnreachable
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.core.ratelimit import RateProfile
from scanner.feeds.msrc import InMemoryMsrcStore, MsrcFix, assess_sql, parse_cvrf
from scanner.modules import db_checks as dc
from scanner.modules.base import ScanContext
from scanner.modules.db_audit import DbAuditModule
from tests.test_auth_inventory import Audit

FAST = RateProfile("t", 1000, 4, 0.0, 3, 2.0)
HOST = "10.0.0.9"
DB_PASSWORD = "Db-Pa55-do-not-leak"
TODAY = date(2026, 11, 5)


def _cred(protocol, cid=1, port=None, db_name=None, targets=()):
    ports = {PROTOCOL_POSTGRESQL: 5432, PROTOCOL_MYSQL: 3306, PROTOCOL_MSSQL: 1433,
             PROTOCOL_ORACLE: 1521}
    return HostCredential(cid, f"db-{protocol}", "password", "scan_ro",
                          port=port or ports[protocol], targets=targets,
                          password=DB_PASSWORD, become="none", protocol=protocol,
                          db_name=db_name)


class FakeDb:
    """Сессия СУБД: ответы по имени запроса из db_checks.QUERIES."""

    def __init__(self, protocol: str, answers: dict[str, object]):
        self.protocol = protocol
        self._by_sql = {sql: name for name, sql in dc.QUERIES[protocol].items()}
        self.answers = answers
        self.executed: list[str] = []
        self.closed = False

    def query(self, sql):
        self.executed.append(sql)
        name = self._by_sql.get(sql)
        value = self.answers.get(name) if name else None
        if value is None or isinstance(value, Exception):
            raise DbQueryError(str(value or f"permission denied for {name}"))
        return list(value)

    def close(self):
        self.closed = True


class FakeMatcher:
    """Сопоставление: PostgreSQL 13.x / Postgres Pro / MySQL -> по одной находке."""
    store = None

    def __init__(self):
        self.calls: list[dict] = []

    def findings_for_package(self, host, *, product, version, **kw):
        self.calls.append({"product": product, "version": version, **kw})
        vid = {"PostgreSQL": "CVE-2024-10979", "Postgres Pro": "BDU:2024-08888",
               "MySQL": "CVE-2024-21096"}.get(product)
        if not vid:
            return []
        return [Finding(module=kw["module"], host=host, port=None,
                        finding_type=FindingType.VULN, title=f"Уязвимость {product}",
                        severity=Severity.HIGH, vuln_id=vid,
                        cve_ids=[vid] if vid.startswith("CVE") else [],
                        evidence=f"Пакет {product} ({version}) → {product} {version}\n"
                                 "[cpe] деталь")]

    def enrich(self, finding):
        finding.bdu_ids = [*finding.bdu_ids, "BDU:2024-00042"]
        return finding


PG_ANSWERS = {
    "version": [("PostgreSQL 13.4 on x86_64-pc-linux-gnu", "130004")],
    "settings": [("ssl", "off"), ("password_encryption", "md5"),
                 ("log_connections", "on"), ("log_disconnections", "off"),
                 ("log_statement", "none"), ("shared_preload_libraries", "")],
    "roles": [("postgres", True, True, None), ("app_admin", True, True, None),
              ("reporting", False, True, None)],
    "hba": [("local", "{all}", "{all}", None, "peer"),
            ("host", "{all}", "{all}", "0.0.0.0", "trust"),
            ("host", "{app}", "{app}", "10.0.0.0", "md5")],
    "public_create": [(True,)],
    "extensions": [("plpgsql", "1.0")],
}


def _ctx(creds, services=None, targets=(HOST,)):
    ctx = ScanContext(engagement_id=1, scan_run_id=1, targets=list(targets), rate=FAST,
                      audit=Audit(), credentials=list(creds))
    if services is not None:
        ctx.services = services
        ctx.completed.add("discovery")
    return ctx


def _run(creds, sessions, *, matcher=None, msrc_store=None, services=None,
         connector=None):
    def default_connector(host, cred, options):
        return sessions[cred.protocol]
    module = DbAuditModule(matcher=matcher if matcher is not None else FakeMatcher(),
                           connector=connector or default_connector,
                           msrc_store=msrc_store, sleep=lambda s: None,
                           today=lambda: TODAY)
    ctx = _ctx(creds, services)
    return module.run(ctx), ctx


# ---------- запросы: только чтение ----------

def test_queries_are_read_only_constants():
    for protocol, queries in dc.QUERIES.items():
        for name, sql in queries.items():
            head = sql.strip().split()[0].upper()
            assert head in ("SELECT", "SHOW"), (protocol, name)
            assert ";" not in sql
            assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|GRANT|CREATE "
                                 r"|EXEC|TRUNCATE)\b", sql.upper()), (protocol, name)


# ---------- определение продукта ----------

@pytest.mark.parametrize(("protocol", "answers", "kind", "version"), [
    (PROTOCOL_POSTGRESQL, {"version": [("PostgreSQL 16.2 (Debian 16.2-1)", "160002")]},
     dc.POSTGRESQL, "16.2"),
    (PROTOCOL_POSTGRESQL, {"version": [("PostgreSQL 9.6.24", "90624")]}, dc.POSTGRESQL,
     "9.6.24"),
    (PROTOCOL_POSTGRESQL, {"version": [("PostgreSQL 15.5", "150005")],
                           "pgpro": [("PostgresPro 15.5.1", "enterprise")]},
     dc.POSTGRESPRO, "15.5.1"),
    (PROTOCOL_MYSQL, {"version": [("8.0.36", "MySQL Community Server - GPL")]},
     dc.MYSQL, "8.0.36"),
    (PROTOCOL_MYSQL, {"version": [("10.11.6-MariaDB-0+deb12u1", "Debian 12")]},
     dc.MARIADB, "10.11.6"),
    (PROTOCOL_MYSQL, {"version": [("5.5.5-10.3.39-MariaDB", "")]}, dc.MARIADB, "10.3.39"),
    (PROTOCOL_MSSQL, {"version": [("15.0.4335.1", "RTM", "Standard Edition", "CU23", 0)]},
     dc.MSSQL, "15.0.4335.1"),
    (PROTOCOL_ORACLE, {"version": [("19.0.0.0.0",)], "version_full": [("19.21.0.0.0",)]},
     dc.ORACLE, "19.21.0.0.0"),
])
def test_detect_product(protocol, answers, kind, version):
    facts = dc.DbFacts(protocol, rows=answers)
    p = dc.detect_product(facts)
    assert p is not None and p.kind == kind and p.version == version


def test_postgrespro_keeps_upstream_and_edition():
    facts = dc.DbFacts(PROTOCOL_POSTGRESQL, rows={
        "version": [("PostgreSQL 15.5", "150005")],
        "pgpro": [("PostgresPro 15.5.1", "standard")]})
    p = dc.detect_product(facts)
    assert p.upstream == "15.5" and p.label == "Postgres Pro Standard 15.5.1"


def test_end_of_support():
    assert dc.end_of_support(dc.DbProduct(dc.POSTGRESQL, "13.4")) == date(2025, 11, 13)
    assert dc.end_of_support(dc.DbProduct(dc.POSTGRESQL, "9.6.24")) == date(2021, 11, 11)
    assert dc.end_of_support(dc.DbProduct(dc.MYSQL, "5.7.44")) == date(2023, 10, 31)
    assert dc.end_of_support(dc.DbProduct(dc.MSSQL, "12.0.6024.0")) == date(2024, 7, 9)
    assert dc.end_of_support(dc.DbProduct(dc.MARIADB, "10.11.6")) == date(2028, 2, 16)
    assert dc.end_of_support(dc.DbProduct(dc.POSTGRESPRO, "15.5.1")) is None
    assert dc.mssql_year("15.0.4335.1") == "2019" and dc.mssql_year("10.50.1600.1") \
        == "2008 R2"


# ---------- правила ----------

def _statuses(protocol, answers):
    return {c.id: r.status for c, r in dc.evaluate(dc.DbFacts(protocol, rows=answers))}


def test_postgresql_rules():
    st = _statuses(PROTOCOL_POSTGRESQL, PG_ANSWERS)
    assert st["DB-PG-SSL"] == dc.FAIL
    assert st["DB-PG-PWENC"] == dc.FAIL
    assert st["DB-PG-HBA-TRUST"] == dc.FAIL and st["DB-PG-HBA-WEAK"] == dc.FAIL
    assert st["DB-PG-SUPERUSER"] == dc.FAIL
    assert st["DB-PG-PUBLIC-CREATE"] == dc.FAIL
    assert st["DB-PG-LOGCONN"] == dc.PASS and st["DB-PG-LOGDISCONN"] == dc.FAIL
    assert st["DB-PG-LOGSTMT"] == dc.FAIL and st["DB-PG-PGAUDIT"] == dc.FAIL


def test_missing_rights_are_unknown_not_pass():
    answers = {"version": PG_ANSWERS["version"], "settings": PG_ANSWERS["settings"]}
    st = _statuses(PROTOCOL_POSTGRESQL, answers)
    assert st["DB-PG-HBA-TRUST"] == dc.UNKNOWN
    assert st["DB-PG-SUPERUSER"] == dc.UNKNOWN
    assert st["DB-PG-SSL"] == dc.FAIL


def test_mysql_rules():
    st = _statuses(PROTOCOL_MYSQL, {
        "version": [("8.0.36", "")],
        "settings": [("local_infile", "ON"), ("secure_file_priv", ""),
                     ("require_secure_transport", "OFF"), ("skip_name_resolve", "OFF"),
                     ("sql_mode", "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES"),
                     ("default_password_lifetime", "0"), ("log_error", "/var/log/e.log")],
        "users": [("root", "localhost", "auth_socket", 1), ("root", "%",
                  "caching_sha2_password", 0), ("app", "%", "mysql_native_password", 1),
                  ("", "localhost", "mysql_native_password", 1)],
        "databases": [("mysql",), ("test",)],
    })
    assert st["DB-MY-EMPTYPW"] == dc.FAIL          # app без пароля; root по сокету — нет
    assert st["DB-MY-ANON"] == dc.FAIL
    assert st["DB-MY-REMOTEROOT"] == dc.FAIL
    assert st["DB-MY-LOCALINFILE"] == dc.FAIL and st["DB-MY-SECUREFILE"] == dc.FAIL
    assert st["DB-MY-TLS"] == dc.FAIL and st["DB-MY-NAMERES"] == dc.FAIL
    assert st["DB-MY-STRICT"] == dc.PASS and st["DB-MY-PWLIFE"] == dc.FAIL
    assert st["DB-MY-LOGERR"] == dc.PASS and st["DB-MY-TESTDB"] == dc.FAIL


def test_mssql_rules():
    st = _statuses(PROTOCOL_MSSQL, {
        "version": [("15.0.4335.1", "RTM", "Standard", "CU23", 0)],
        "settings": [("xp_cmdshell", 1), ("Ad Hoc Distributed Queries", 0),
                     ("clr enabled", 0), ("remote admin connections", 1)],
        "logins": [("sa", 1, 0, 1, 0), ("app", 270, 0, 0, 0), ("old", 271, 1, 0, 0),
                   ("##MS_PolicyTsqlExecutionLogin##", 256, 0, 0, 0)],
    })
    assert st["DB-MS-XPCMD"] == dc.FAIL and st["DB-MS-ADHOC"] == dc.PASS
    assert st["DB-MS-DAC"] == dc.FAIL
    assert st["DB-MS-OLE"] == dc.UNKNOWN            # параметр не прочитан
    assert st["DB-MS-SA"] == dc.FAIL and st["DB-MS-SANAME"] == dc.FAIL
    assert st["DB-MS-POLICY"] == dc.FAIL and st["DB-MS-EXPIRATION"] == dc.FAIL
    assert st["DB-MS-MIXED"] == dc.FAIL


def test_oracle_rules():
    st = _statuses(PROTOCOL_ORACLE, {
        "version": [("19.0.0.0.0",)],
        "settings": [("remote_os_authent", "FALSE"), ("remote_os_roles", "TRUE"),
                     ("audit_trail", "NONE"), ("sql92_security", "TRUE")],
        "profiles": [("DEFAULT", "FAILED_LOGIN_ATTEMPTS", "UNLIMITED"),
                     ("DEFAULT", "PASSWORD_LIFE_TIME", "180"),
                     ("DEFAULT", "PASSWORD_VERIFY_FUNCTION", "NULL")],
        "public_exec": [("UTL_FILE",), ("UTL_HTTP",)],
    })
    assert st["DB-ORA-REMOTEOS"] == dc.PASS and st["DB-ORA-REMOTEROLES"] == dc.FAIL
    assert st["DB-ORA-AUDIT"] == dc.FAIL and st["DB-ORA-SQL92"] == dc.PASS
    assert st["DB-ORA-FAILEDLOGIN"] == dc.FAIL and st["DB-ORA-PWLIFE"] == dc.PASS
    assert st["DB-ORA-PWVERIFY"] == dc.FAIL and st["DB-ORA-PUBLICEXEC"] == dc.FAIL
    assert st["DB-ORA-DEFPWD"] == dc.UNKNOWN       # нет прав на dba_users_with_defpwd


# ---------- модуль целиком ----------

def test_postgres_run_findings_coverage_and_safety():
    db = FakeDb(PROTOCOL_POSTGRESQL, PG_ANSWERS)
    matcher = FakeMatcher()
    findings, ctx = _run([_cred(PROTOCOL_POSTGRESQL)], {PROTOCOL_POSTGRESQL: db},
                         matcher=matcher)
    by_id = {f.vuln_id: f for f in findings}
    assert db.closed
    # версия -> CVE (NVD по CPE) на порту СУБД, с пометкой источника
    vuln = by_id["CVE-2024-10979"]
    assert vuln.module == "db_audit" and vuln.port == 5432
    assert "PostgreSQL 13.4 на порту 5432" in vuln.evidence
    assert "Пакет" not in vuln.evidence
    assert matcher.calls[0]["cpe"] == "cpe:/a:postgresql:postgresql"
    # ветка 13 не поддерживается с 13.11.2025
    eol = by_id["DB-EOL"]
    assert eol.severity == Severity.HIGH and "13.11.2025" in eol.title
    # конфигурация
    trust = by_id["DB-PG-HBA-TRUST"]
    assert trust.finding_type == FindingType.CONFIG and trust.severity == Severity.HIGH
    assert "0.0.0.0" in trust.evidence and "scram-sha-256" in trust.remediation
    assert "CIS PostgreSQL" in trust.remediation
    summary = by_id["INFO:db-audit"]
    assert "PostgreSQL 13.4" in summary.title and "нарушено" in summary.evidence
    assert ctx.coverage.status(HOST, "db_audit") == cv.COMPLETED
    # пароль нигде не виден
    assert DB_PASSWORD not in repr(ctx.audit.records)
    assert all(DB_PASSWORD not in (f.evidence or "") for f in findings)
    assert ctx.compliance_facts[HOST]["dbms:5432"]["product"] == "postgresql"


def test_postgrespro_matches_bdu_and_upstream():
    answers = dict(PG_ANSWERS, version=[("PostgreSQL 16.2", "160002")],
                   pgpro=[("PostgresPro 16.2.1", "enterprise")])
    matcher = FakeMatcher()
    findings, _ = _run([_cred(PROTOCOL_POSTGRESQL)],
                       {PROTOCOL_POSTGRESQL: FakeDb(PROTOCOL_POSTGRESQL, answers)},
                       matcher=matcher)
    ids = {f.vuln_id for f in findings}
    assert {"BDU:2024-08888", "CVE-2024-10979"} <= ids
    pro = next(c for c in matcher.calls if c["product"] == "Postgres Pro")
    assert pro["version"] == "16.2.1" and pro["cpe"] is None
    assert "Postgres Pro Enterprise" in pro["bdu_names"]
    up = next(c for c in matcher.calls if c["product"] == "PostgreSQL")
    assert up["version"] == "16.2"
    assert "DB-EOL" not in ids


def test_mssql_uses_msrc_branch():
    store = InMemoryMsrcStore([
        # CU-ветка: исправление в 15.0.4360.2 — экземпляр 15.0.4335.1 уязвим
        MsrcFix("2024-Jul", "CVE-2024-21332", "1", "Microsoft SQL Server 2019 for "
                "x64-based Systems (CU 27)", "5040948", fixed_build="15.0.4382.1",
                severity="Important", cvss=8.8, title="SQL Server RCE"),
        MsrcFix("2024-Jul", "CVE-2024-21332", "2", "Microsoft SQL Server 2019 for "
                "x64-based Systems (CU 25)", "5040949", fixed_build="15.0.4360.2",
                severity="Important", cvss=8.8, title="SQL Server RCE"),
        # GDR-ветка — к экземпляру на CU не относится
        MsrcFix("2024-Jul", "CVE-2024-99999", "3", "Microsoft SQL Server 2019 for "
                "x64-based Systems (GDR)", "5040986", fixed_build="15.0.2116.2",
                severity="Important", cvss=8.8, title="только GDR"),
        # закрыта: исправление старше сборки экземпляра
        MsrcFix("2023-Feb", "CVE-2023-21528", "4", "Microsoft SQL Server 2019 for "
                "x64-based Systems (CU 18)", "5021124", fixed_build="15.0.4280.7",
                severity="Important", cvss=7.8, title="старое"),
    ])
    a = assess_sql("15.0.4335.1", "2019", store)
    assert [g.cve_id for g in a.gaps] == ["CVE-2024-21332"] and a.fixed == 1
    assert a.gaps[0].fixed_build == "15.0.4360.2" and a.gaps[0].recommended_kb == "5040948"

    answers = {"version": [("15.0.4335.1", "RTM", "Standard Edition", "CU23", 1)],
               "settings": [("xp_cmdshell", 0)], "logins": []}
    findings, _ = _run([_cred(PROTOCOL_MSSQL)],
                         {PROTOCOL_MSSQL: FakeDb(PROTOCOL_MSSQL, answers)},
                         msrc_store=store)
    gap = next(f for f in findings if f.vuln_id == "CVE-2024-21332")
    assert gap.port == 1433 and gap.severity == Severity.HIGH
    assert "KB5040948" in gap.remediation and "BDU:2024-00042" in gap.bdu_ids
    assert gap.confidence == "high"


def test_mssql_without_msrc_is_no_data_not_clean():
    answers = {"version": [("16.0.4135.4", "RTM", "Developer", "CU15", 1)]}
    findings, ctx = _run([_cred(PROTOCOL_MSSQL)],
                         {PROTOCOL_MSSQL: FakeDb(PROTOCOL_MSSQL, answers)})
    summary = next(f for f in findings if f.vuln_id == "INFO:db-audit")
    assert "справочник MSRC не загружен" in summary.evidence
    assert any(n["kind"] == "msrc_missing" for n in ctx.run_notes)


def test_msrc_parse_keeps_sql_server_products():
    doc = {"ProductTree": {"FullProductName": [
        {"ProductID": "1", "Value": "Microsoft SQL Server 2019 for x64-based Systems (CU 25)"},
        {"ProductID": "2", "Value": "Microsoft Office 2019"}]},
        "Vulnerability": [{"CVE": "CVE-2024-21332", "Remediations": [
            {"Type": 2, "Description": {"Value": "5040948"}, "ProductID": ["1", "2"],
             "FixedBuild": "15.0.4360.2"}]}]}
    fixes = parse_cvrf(doc, "2024-Jul")
    assert [f.product for f in fixes] == [
        "Microsoft SQL Server 2019 for x64-based Systems (CU 25)"]


def test_missing_rights_listed_in_summary():
    answers = {"version": [("8.0.40", "")], "settings": [("local_infile", "OFF")]}
    findings, _ = _run([_cred(PROTOCOL_MYSQL)],
                       {PROTOCOL_MYSQL: FakeDb(PROTOCOL_MYSQL, answers)})
    summary = next(f for f in findings if f.vuln_id == "INFO:db-audit")
    assert "не проверено" in summary.evidence
    assert "SELECT ON mysql.user" in summary.evidence


def test_only_db_credentials_used():
    ssh = HostCredential(5, "ssh", "password", "root", port=22, password="x",
                         protocol=PROTOCOL_SSH)
    called = []
    findings, ctx = _run([ssh], {}, connector=lambda *a: called.append(a))
    assert findings == [] and not called
    assert ctx.coverage.status(HOST, "db_audit") == cv.NOT_APPLICABLE


def test_credential_scope_respected():
    cred = _cred(PROTOCOL_POSTGRESQL, targets=("10.9.9.0/24",))
    called = []
    _run([cred], {}, connector=lambda *a: called.append(a))
    assert not called


def test_discovery_gates_ports_and_reports_db_without_credential():
    services = [ServiceInfo(host=HOST, port=22, protocol="tcp", service="ssh"),
                ServiceInfo(host=HOST, port=3306, protocol="tcp", service="mysql")]
    called = []
    _, ctx = _run([_cred(PROTOCOL_POSTGRESQL)], {},
                         services=services, connector=lambda *a: called.append(a))
    assert not called                                 # 5432 закрыт — не подключаемся
    entry = ctx.coverage.get(HOST, "db_audit")
    assert entry.status == cv.NO_CREDENTIALS and "MySQL" in entry.reason


def test_auth_failure_tries_next_credential_then_succeeds():
    db = FakeDb(PROTOCOL_POSTGRESQL, PG_ANSWERS)
    tried = []

    def connector(host, cred, options):
        tried.append(cred.id)
        if cred.id == 1:
            raise DbAuthFailed("password authentication failed")
        return db
    creds = [_cred(PROTOCOL_POSTGRESQL, cid=1), _cred(PROTOCOL_POSTGRESQL, cid=2)]
    findings, ctx = _run(creds, {}, connector=connector)
    assert tried == [1, 2]
    assert "INFO:db-audit-auth-failed" not in {f.vuln_id for f in findings}
    assert ctx.coverage.status(HOST, "db_audit") == cv.COMPLETED


def test_unreachable_marks_gap():
    def connector(host, cred, options):
        raise DbUnreachable("connection timed out")
    findings, ctx = _run([_cred(PROTOCOL_ORACLE, db_name="ORCLPDB1")], {},
                         connector=connector)
    assert {f.vuln_id for f in findings} == {"INFO:db-audit-unreachable"}
    assert ctx.coverage.status(HOST, "db_audit") == cv.TIMEOUT


# ---------- учётки СУБД ----------

def test_validate_db_name():
    assert validate_db_name(PROTOCOL_POSTGRESQL, None) == "postgres"
    assert validate_db_name(PROTOCOL_MSSQL, "") == "master"
    assert validate_db_name(PROTOCOL_MYSQL, None) is None
    assert validate_db_name(PROTOCOL_SSH, "x") is None
    with pytest.raises(CredentialError):
        validate_db_name(PROTOCOL_ORACLE, None)
    with pytest.raises(CredentialError):
        validate_db_name(PROTOCOL_POSTGRESQL, "x'; drop")


def test_dbexec_scrubs_password_from_errors():
    from scanner.core.dbexec import _clean
    cred = _cred(PROTOCOL_MYSQL)
    assert DB_PASSWORD not in _clean(RuntimeError(f"bad {DB_PASSWORD}"), cred)


# ---------- состав прогона ----------

def test_profile_and_plan_for_dbms():
    from scanner.api.rbac import MODULE_PERMISSIONS, Perm
    from scanner.core.orchestrator import (
        CREDENTIAL_MODULES,
        MODULE_ORDER,
        default_module_registry,
    )
    from scanner.core.profiles import PROFILES, plan_modules
    assert "db_audit" in MODULE_ORDER and "db_audit" in CREDENTIAL_MODULES
    assert MODULE_PERMISSIONS["db_audit"] is Perm.HOST_CREDENTIALS
    assert "db_audit" in default_module_registry()
    prof = PROFILES["dbms"]
    assert prof.modules == ("discovery", "db_audit") and prof.needs == ("dbms",)
    ok = plan_modules(prof.modules, protocols={"postgresql"})
    assert ok.names == ["discovery", "db_audit"] and not any("СУБД" in w
                                                             for w in ok.warnings)
    no = plan_modules(prof.modules, protocols={"ssh"})
    assert any("нет учётки СУБД" in w for w in no.warnings)
