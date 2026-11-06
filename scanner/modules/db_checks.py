"""Аудит СУБД: фиксированные запросы на чтение, определение продукта и версии,
правила конфигурации по мотивам CIS Benchmarks (db_audit).

Всё здесь — чистые функции над уже собранными данными (`DbFacts`), без сети:
так правила проверяются тестами на образцах вывода.

Запросы (`QUERIES`) — только SELECT/SHOW из кода, без подстановки входных
данных. Учётке СУБД нужны права только на чтение системных представлений; если
какого-то права нет, запрос попадает в `DbFacts.unavailable`, а зависящие от
него правила получают статус «не проверено» (UNKNOWN) — не «выполнено».

Правила — по мотивам CIS Benchmarks для PostgreSQL, MySQL, MariaDB, Microsoft
SQL Server и Oracle Database (разделы аутентификации, журналирования, сетевого
доступа и опасных функций). Номера пунктов CIS не указываются: формулировки
бенчмарков меняются от версии к версии, правило ссылается на раздел.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from scanner.core.credentials import (
    PROTOCOL_MSSQL,
    PROTOCOL_MYSQL,
    PROTOCOL_ORACLE,
    PROTOCOL_POSTGRESQL,
)
from scanner.core.models import Severity

# Продукты (вид СУБД после определения версии).
POSTGRESQL = "postgresql"
POSTGRESPRO = "postgrespro"
MYSQL = "mysql"
MARIADB = "mariadb"
MSSQL = "mssql"
ORACLE = "oracle"

PRODUCT_LABELS = {POSTGRESQL: "PostgreSQL", POSTGRESPRO: "Postgres Pro", MYSQL: "MySQL",
                  MARIADB: "MariaDB", MSSQL: "Microsoft SQL Server",
                  ORACLE: "Oracle Database"}

# ---------- запросы ----------
#
# Имя -> SQL. Порядок важен только для «version»: он первый. Необязательные
# запросы (pgpro — только у Postgres Pro, version_full — Oracle 18c+) тоже
# попадают в unavailable, но правила на них не опираются.

QUERIES: dict[str, dict[str, str]] = {
    PROTOCOL_POSTGRESQL: {
        "version": "SELECT version(), current_setting('server_version_num')",
        "pgpro": "SELECT pgpro_version(), pgpro_edition()",
        "settings": "SELECT name, setting FROM pg_settings",
        "roles": ("SELECT rolname, rolsuper, rolcanlogin, rolvaliduntil::text "
                  "FROM pg_roles"),
        "hba": ("SELECT type, database::text, user_name::text, address, auth_method "
                "FROM pg_hba_file_rules"),
        "public_create": "SELECT has_schema_privilege('public', 'public', 'CREATE')",
        "extensions": "SELECT extname, extversion FROM pg_extension",
    },
    PROTOCOL_MYSQL: {
        "version": "SELECT VERSION(), @@version_comment",
        "settings": "SHOW GLOBAL VARIABLES",
        "users": ("SELECT user, host, plugin, CASE WHEN authentication_string IS NULL "
                  "OR authentication_string = '' THEN 1 ELSE 0 END FROM mysql.user"),
        "databases": "SHOW DATABASES",
    },
    PROTOCOL_MSSQL: {
        "version": ("SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), "
                    "CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)), "
                    "CAST(SERVERPROPERTY('Edition') AS nvarchar(128)), "
                    "CAST(SERVERPROPERTY('ProductUpdateLevel') AS nvarchar(128)), "
                    "CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int)"),
        "settings": "SELECT name, CAST(value_in_use AS int) FROM sys.configurations",
        "logins": ("SELECT name, principal_id, CAST(is_disabled AS int), "
                   "CAST(is_policy_checked AS int), CAST(is_expiration_checked AS int) "
                   "FROM sys.sql_logins"),
    },
    PROTOCOL_ORACLE: {
        "version": "SELECT version FROM product_component_version",
        "version_full": "SELECT version_full FROM product_component_version",
        "settings": "SELECT name, value FROM v$parameter",
        "profiles": ("SELECT profile, resource_name, limit FROM dba_profiles "
                     "WHERE resource_type = 'PASSWORD'"),
        "default_pwd": "SELECT username FROM dba_users_with_defpwd",
        "public_exec": ("SELECT table_name FROM dba_tab_privs WHERE grantee = 'PUBLIC' "
                        "AND privilege = 'EXECUTE' AND table_name IN ('UTL_FILE', "
                        "'UTL_TCP', 'UTL_HTTP', 'UTL_SMTP', 'UTL_INADDR', 'DBMS_JAVA', "
                        "'DBMS_ADVISOR', 'DBMS_LOB', 'DBMS_SQL', 'DBMS_XMLGEN', "
                        "'DBMS_BACKUP_RESTORE', 'DBMS_SCHEDULER')"),
    },
}

# Запросы, отсутствие которых нормально (не «нет прав»).
OPTIONAL_QUERIES = frozenset({"pgpro", "version_full"})

# Что нужно учётке, чтобы запрос выполнился — для пояснений «не проверено».
QUERY_GRANTS: dict[str, dict[str, str]] = {
    PROTOCOL_POSTGRESQL: {
        "settings": "роль pg_read_all_settings (или pg_monitor)",
        "hba": "GRANT SELECT ON pg_hba_file_rules и GRANT EXECUTE ON FUNCTION "
               "pg_hba_file_rules() (роли pg_read_all_settings для этого мало)",
    },
    PROTOCOL_MYSQL: {"users": "SELECT ON mysql.user (столбцы user, host, plugin, "
                              "authentication_string)"},
    PROTOCOL_MSSQL: {"settings": "VIEW SERVER STATE",
                     "logins": "VIEW ANY DEFINITION (SQL Server 2022: VIEW SERVER "
                               "SECURITY STATE)"},
    PROTOCOL_ORACLE: {"settings": "SELECT_CATALOG_ROLE",
                      "profiles": "SELECT_CATALOG_ROLE",
                      "default_pwd": "SELECT ON dba_users_with_defpwd (выдаёт DBA)",
                      "public_exec": "SELECT_CATALOG_ROLE"},
}


@dataclass(slots=True)
class DbFacts:
    """Результаты запросов к одному экземпляру СУБД."""
    protocol: str
    rows: dict[str, list[tuple[Any, ...]]] = field(default_factory=dict)
    unavailable: dict[str, str] = field(default_factory=dict)   # запрос -> причина

    def has(self, name: str) -> bool:
        return name in self.rows

    def first(self, name: str) -> tuple[Any, ...] | None:
        rows = self.rows.get(name) or []
        return rows[0] if rows else None

    @property
    def settings(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for row in self.rows.get("settings") or []:
            if len(row) >= 2 and row[0] is not None:
                out[str(row[0]).strip().lower()] = "" if row[1] is None else str(row[1])
        return out


# ---------- продукт и версия ----------

@dataclass(frozen=True, slots=True)
class DbProduct:
    kind: str                       # postgresql | postgrespro | mysql | mariadb | mssql | oracle
    version: str                    # версия для сопоставления: 16.2, 10.11.6, 15.0.4335.1
    raw: str = ""                   # как сообщила СУБД
    edition: str | None = None
    upstream: str | None = None     # Postgres Pro: версия PostgreSQL, на которой основан

    @property
    def label(self) -> str:
        name = PRODUCT_LABELS.get(self.kind, self.kind)
        if self.edition and self.kind == POSTGRESPRO:
            name = f"{name} {self.edition.capitalize()}"
        return f"{name} {self.version}".strip()

    @property
    def major(self) -> tuple[int, ...]:
        nums = [int(x) for x in re.findall(r"\d+", self.version)[:2]]
        return tuple(nums)


_VER_RE = re.compile(r"(\d+(?:\.\d+){1,4})")


def _pg_version_num(num: Any) -> str | None:
    try:
        n = int(str(num).strip())
    except (TypeError, ValueError):
        return None
    if n >= 100000:                         # 10+: 160002 -> 16.2
        return f"{n // 10000}.{n % 10000}"
    return f"{n // 10000}.{(n // 100) % 100}.{n % 100}"   # 9.6.24


def detect_product(facts: DbFacts) -> DbProduct | None:
    """Продукт и версия по ответу СУБД; None — версия не прочитана."""
    v = facts.first("version")
    if v is None:
        return None
    p = facts.protocol
    if p == PROTOCOL_POSTGRESQL:
        raw = str(v[0] or "")
        upstream = _pg_version_num(v[1] if len(v) > 1 else None)
        if upstream is None:
            m = re.search(r"PostgreSQL (\d+(?:\.\d+)*)", raw)
            upstream = m.group(1) if m else None
        pro = facts.first("pgpro")
        if pro is not None and pro[0]:
            m = _VER_RE.search(str(pro[0]))
            if m:
                return DbProduct(POSTGRESPRO, m.group(1), raw=str(pro[0]),
                                 edition=str(pro[1]).strip().lower() if len(pro) > 1
                                 and pro[1] else None, upstream=upstream)
        if upstream is None:
            return None
        return DbProduct(POSTGRESQL, upstream, raw=raw)
    if p == PROTOCOL_MYSQL:
        raw = str(v[0] or "")
        comment = str(v[1] or "") if len(v) > 1 else ""
        m = _VER_RE.search(raw)
        if not m:
            return None
        ver = m.group(1)
        # MariaDB 10.x в старых сборках отдавала «5.5.5-10.x.y-MariaDB»
        mm = re.search(r"5\.5\.5-(\d+\.\d+\.\d+)", raw)
        if mm:
            ver = mm.group(1)
        kind = MARIADB if "mariadb" in (raw + " " + comment).lower() else MYSQL
        return DbProduct(kind, ver, raw=raw, edition=comment or None)
    if p == PROTOCOL_MSSQL:
        raw = str(v[0] or "")
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", raw.strip()):
            return None
        level = " ".join(str(x) for x in v[1:4] if x)
        return DbProduct(MSSQL, raw.strip(), raw=f"{raw} {level}".strip(),
                         edition=str(v[2]) if len(v) > 2 and v[2] else None)
    if p == PROTOCOL_ORACLE:
        full = facts.first("version_full")
        raw = str((full[0] if full and full[0] else v[0]) or "")
        m = _VER_RE.search(raw)
        if not m:
            return None
        return DbProduct(ORACLE, m.group(1), raw=raw)
    return None


# Названия года SQL Server по старшему номеру версии.
MSSQL_YEARS = {10: "2008", 11: "2012", 12: "2014", 13: "2016", 14: "2017", 15: "2019",
               16: "2022", 17: "2025"}


def mssql_year(version: str) -> str | None:
    parts = version.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return None
    if major == 10 and minor >= 50:
        return "2008 R2"
    return MSSQL_YEARS.get(major)


# ---------- окончание поддержки ----------
#
# Даты окончания поддержки производителем (после них исправлений безопасности
# нет). Только ветки с известной датой; неизвестные — без вывода.

EOL: dict[str, dict[tuple[int, ...], date]] = {
    POSTGRESQL: {(9, 6): date(2021, 11, 11), (10,): date(2022, 11, 10),
                 (11,): date(2023, 11, 9), (12,): date(2024, 11, 21),
                 (13,): date(2025, 11, 13), (14,): date(2026, 11, 12),
                 (15,): date(2027, 11, 11), (16,): date(2028, 11, 9),
                 (17,): date(2029, 11, 8)},
    MYSQL: {(5, 5): date(2018, 12, 31), (5, 6): date(2021, 2, 28),
            (5, 7): date(2023, 10, 31), (8, 0): date(2026, 4, 30)},
    MARIADB: {(10, 2): date(2022, 5, 23), (10, 3): date(2023, 5, 25),
              (10, 4): date(2024, 6, 18), (10, 5): date(2025, 6, 24),
              (10, 6): date(2026, 7, 6), (10, 7): date(2023, 2, 9),
              (10, 8): date(2023, 5, 20), (10, 9): date(2023, 8, 22),
              (10, 10): date(2023, 11, 17), (10, 11): date(2028, 2, 16),
              (11, 0): date(2024, 6, 6), (11, 1): date(2024, 8, 21),
              (11, 2): date(2024, 11, 21), (11, 3): date(2025, 5, 29),
              (11, 4): date(2029, 5, 29)},
    MSSQL: {(10,): date(2019, 7, 9), (11,): date(2022, 7, 12), (12,): date(2024, 7, 9),
            (13,): date(2026, 7, 14), (14,): date(2027, 10, 12),
            (15,): date(2030, 1, 8), (16,): date(2033, 1, 11)},
    ORACLE: {(11,): date(2020, 12, 31), (12,): date(2022, 7, 31),
             (18,): date(2021, 6, 30)},
}


def end_of_support(product: DbProduct) -> date | None:
    """Дата окончания поддержки ветки продукта (None — неизвестна)."""
    table = EOL.get(POSTGRESQL if product.kind == POSTGRESQL else product.kind)
    if not table:
        return None
    nums = product.major
    for n in (2, 1):
        if len(nums) >= n and tuple(nums[:n]) in table:
            if product.kind == POSTGRESQL and n == 2 and nums[0] >= 10:
                continue                      # 10+: ветка — одно число
            return table[tuple(nums[:n])]
    return None


# ---------- правила конфигурации ----------

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: str
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class DbCheck:
    id: str                         # DB-PG-SSL — vuln_id находки
    protocol: str
    title: str                      # формулировка нарушения
    severity: Severity
    remediation: str
    reference: str                  # раздел CIS Benchmark
    needs: tuple[str, ...]          # запросы, без которых правило не проверить
    fn: Callable[[DbFacts], CheckResult]


def _on(v: str | None) -> bool:
    return (v or "").strip().lower() in ("on", "1", "true", "yes")


def _setting(name: str, bad: Callable[[str], bool], show: str | None = None
             ) -> Callable[[DbFacts], CheckResult]:
    def fn(f: DbFacts) -> CheckResult:
        s = f.settings
        if name not in s:
            return CheckResult(UNKNOWN, f"параметр {show or name} не прочитан")
        value = s[name]
        return CheckResult(FAIL if bad(value) else PASS, f"{show or name} = {value!r}")
    return fn


# --- PostgreSQL ---

def _pg_hba_methods(bad: set[str]) -> Callable[[DbFacts], CheckResult]:
    def fn(f: DbFacts) -> CheckResult:
        hits = []
        for row in f.rows.get("hba") or []:
            typ, db, users, addr, method = (list(row) + [None] * 5)[:5]
            if str(method or "").lower() in bad and str(typ or "") != "local":
                hits.append(f"{typ} {db} {users} {addr or ''} {method}".strip())
        if hits:
            return CheckResult(FAIL, "pg_hba.conf:\n" + "\n".join(hits[:20]))
        return CheckResult(PASS, "в pg_hba.conf нет таких сетевых правил")
    return fn


def _pg_superusers(f: DbFacts) -> CheckResult:
    names = [str(r[0]) for r in f.rows.get("roles") or []
             if len(r) > 2 and _on(str(r[1])) and _on(str(r[2]))]
    extra = [n for n in names if n != "postgres"]
    if extra:
        return CheckResult(FAIL, "суперпользователи с правом входа: " + ", ".join(names))
    return CheckResult(PASS, "суперпользователи с правом входа: "
                       + (", ".join(names) or "нет"))


def _pg_public_create(f: DbFacts) -> CheckResult:
    row = f.first("public_create")
    if row is None:
        return CheckResult(UNKNOWN)
    return CheckResult(FAIL if _on(str(row[0])) else PASS,
                       f"CREATE на схеме public для PUBLIC: {row[0]}")


def _pg_pgaudit(f: DbFacts) -> CheckResult:
    s = f.settings
    if "shared_preload_libraries" not in s:
        return CheckResult(UNKNOWN)
    libs = s["shared_preload_libraries"]
    return CheckResult(PASS if "pgaudit" in libs.lower() else FAIL,
                       f"shared_preload_libraries = {libs!r}")


def _pg_log_statement(f: DbFacts) -> CheckResult:
    s = f.settings
    if "log_statement" not in s:
        return CheckResult(UNKNOWN)
    v = s["log_statement"].lower()
    return CheckResult(FAIL if v == "none" else PASS, f"log_statement = {v!r}")


# --- MySQL / MariaDB ---

_SOCKET_PLUGINS = {"auth_socket", "unix_socket", "auth_pam", "authentication_pam",
                   "auth_gssapi_client", "gssapi"}


def _my_empty_passwords(f: DbFacts) -> CheckResult:
    if not f.has("users"):
        return CheckResult(UNKNOWN)
    hits = [f"'{r[0]}'@'{r[1]}'" for r in f.rows["users"]
            if len(r) > 3 and str(r[3]) == "1" and str(r[0] or "")
            and str(r[2] or "").lower() not in _SOCKET_PLUGINS]
    # Роли MariaDB/MySQL 8 (без входа) имеют пустой хэш — их не считаем.
    hits = [h for h in hits if not h.endswith("@''")]
    if hits:
        return CheckResult(FAIL, "без пароля: " + ", ".join(hits[:20]))
    return CheckResult(PASS, "учётных записей без пароля нет")


def _my_anonymous(f: DbFacts) -> CheckResult:
    if not f.has("users"):
        return CheckResult(UNKNOWN)
    hits = [f"''@'{r[1]}'" for r in f.rows["users"] if len(r) > 1 and not str(r[0] or "")]
    if hits:
        return CheckResult(FAIL, "анонимные учётные записи: " + ", ".join(hits))
    return CheckResult(PASS, "анонимных учётных записей нет")


def _my_remote_root(f: DbFacts) -> CheckResult:
    if not f.has("users"):
        return CheckResult(UNKNOWN)
    local = {"localhost", "127.0.0.1", "::1"}
    hits = [f"'root'@'{r[1]}'" for r in f.rows["users"]
            if len(r) > 1 and str(r[0]) == "root" and str(r[1]) not in local]
    if hits:
        return CheckResult(FAIL, "root доступен по сети: " + ", ".join(hits))
    return CheckResult(PASS, "root только с локального адреса")


def _my_test_db(f: DbFacts) -> CheckResult:
    if not f.has("databases"):
        return CheckResult(UNKNOWN)
    names = {str(r[0]).lower() for r in f.rows["databases"] if r}
    return CheckResult(FAIL if "test" in names else PASS,
                       "база test " + ("есть" if "test" in names else "отсутствует"))


def _my_secure_transport(f: DbFacts) -> CheckResult:
    s = f.settings
    if "require_secure_transport" not in s:
        return CheckResult(UNKNOWN, "require_secure_transport не поддерживается")
    return CheckResult(FAIL if not _on(s["require_secure_transport"]) else PASS,
                       f"require_secure_transport = {s['require_secure_transport']!r}")


def _my_strict_mode(f: DbFacts) -> CheckResult:
    s = f.settings
    if "sql_mode" not in s:
        return CheckResult(UNKNOWN)
    mode = s["sql_mode"].upper()
    ok = "STRICT_ALL_TABLES" in mode or "STRICT_TRANS_TABLES" in mode
    return CheckResult(PASS if ok else FAIL, f"sql_mode = {s['sql_mode']!r}")


def _my_password_lifetime(f: DbFacts) -> CheckResult:
    s = f.settings
    if "default_password_lifetime" not in s:
        return CheckResult(UNKNOWN)
    try:
        days = int(s["default_password_lifetime"])
    except ValueError:
        return CheckResult(UNKNOWN)
    return CheckResult(FAIL if days == 0 or days > 365 else PASS,
                       f"default_password_lifetime = {days}")


# --- MS SQL Server ---

def _ms_option(name: str) -> Callable[[DbFacts], CheckResult]:
    def fn(f: DbFacts) -> CheckResult:
        s = f.settings
        if name not in s:
            return CheckResult(UNKNOWN, f"параметр «{name}» не прочитан")
        return CheckResult(FAIL if s[name].strip() == "1" else PASS,
                           f"{name} = {s[name]}")
    return fn


def _ms_sa(f: DbFacts) -> CheckResult:
    if not f.has("logins"):
        return CheckResult(UNKNOWN)
    for r in f.rows["logins"]:
        if len(r) > 2 and str(r[1]) == "1":
            enabled = str(r[2]) == "0"
            return CheckResult(FAIL if enabled else PASS,
                               f"учётная запись sa (сейчас «{r[0]}») "
                               + ("включена" if enabled else "отключена"))
    return CheckResult(UNKNOWN, "учётная запись sa не видна")


def _ms_sa_renamed(f: DbFacts) -> CheckResult:
    if not f.has("logins"):
        return CheckResult(UNKNOWN)
    for r in f.rows["logins"]:
        if len(r) > 1 and str(r[1]) == "1":
            return CheckResult(FAIL if str(r[0]).lower() == "sa" else PASS,
                               f"имя учётной записи с principal_id 1: «{r[0]}»")
    return CheckResult(UNKNOWN)


def _ms_policy(col: int, what: str) -> Callable[[DbFacts], CheckResult]:
    def fn(f: DbFacts) -> CheckResult:
        if not f.has("logins"):
            return CheckResult(UNKNOWN)
        hits = [str(r[0]) for r in f.rows["logins"]
                if len(r) > col and str(r[2]) == "0" and str(r[col]) == "0"
                and not str(r[0]).startswith("##")]
        if hits:
            return CheckResult(FAIL, f"включённые SQL-логины без {what}: "
                               + ", ".join(hits[:20]))
        return CheckResult(PASS, f"все включённые SQL-логины с {what}")
    return fn


def _ms_mixed_mode(f: DbFacts) -> CheckResult:
    v = f.first("version")
    if v is None or len(v) < 5 or v[4] is None:
        return CheckResult(UNKNOWN)
    integrated = str(v[4]) == "1"
    return CheckResult(PASS if integrated else FAIL,
                       "проверка подлинности: "
                       + ("только Windows" if integrated else "смешанная (Windows и SQL Server)"))


# --- Oracle ---

def _ora_param(name: str, bad: Callable[[str], bool]) -> Callable[[DbFacts], CheckResult]:
    return _setting(name, bad)


def _ora_profile_limit(resource: str, bad: Callable[[str], bool]
                       ) -> Callable[[DbFacts], CheckResult]:
    def fn(f: DbFacts) -> CheckResult:
        if not f.has("profiles"):
            return CheckResult(UNKNOWN)
        hits = [f"{r[0]}: {r[2]}" for r in f.rows["profiles"]
                if len(r) > 2 and str(r[1]).upper() == resource and bad(str(r[2]).upper())]
        if hits:
            return CheckResult(FAIL, f"{resource}: " + "; ".join(hits[:20]))
        return CheckResult(PASS, f"{resource}: ограничение задано во всех профилях")
    return fn


def _ora_default_pwd(f: DbFacts) -> CheckResult:
    if not f.has("default_pwd"):
        return CheckResult(UNKNOWN)
    names = [str(r[0]) for r in f.rows["default_pwd"] if r]
    if names:
        return CheckResult(FAIL, "учётные записи с паролем по умолчанию: "
                           + ", ".join(names[:30]))
    return CheckResult(PASS, "учётных записей с паролем по умолчанию нет")


def _ora_public_exec(f: DbFacts) -> CheckResult:
    if not f.has("public_exec"):
        return CheckResult(UNKNOWN)
    names = sorted({str(r[0]) for r in f.rows["public_exec"] if r})
    if names:
        return CheckResult(FAIL, "EXECUTE для PUBLIC: " + ", ".join(names))
    return CheckResult(PASS, "опасные пакеты PUBLIC недоступны")


def _unlimited(v: str) -> bool:
    return v in ("UNLIMITED", "")


_PG, _MY, _MS, _ORA = PROTOCOL_POSTGRESQL, PROTOCOL_MYSQL, PROTOCOL_MSSQL, PROTOCOL_ORACLE
_S = Severity

CHECKS: tuple[DbCheck, ...] = (
    # PostgreSQL / Postgres Pro
    DbCheck("DB-PG-SSL", _PG, "PostgreSQL принимает подключения без TLS (ssl = off)",
            _S.MEDIUM, "Включите TLS: ssl = on, ssl_cert_file/ssl_key_file в "
            "postgresql.conf; в pg_hba.conf используйте hostssl вместо host.",
            "CIS PostgreSQL: подключения и вход", ("settings",),
            _setting("ssl", lambda v: not _on(v))),
    DbCheck("DB-PG-PWENC", _PG, "Пароли PostgreSQL хранятся не в SCRAM-SHA-256",
            _S.MEDIUM, "Установите password_encryption = scram-sha-256, смените пароли "
            "учётных записей и замените md5 на scram-sha-256 в pg_hba.conf.",
            "CIS PostgreSQL: подключения и вход", ("settings",),
            _setting("password_encryption", lambda v: v.lower() not in
                     ("scram-sha-256",))),
    DbCheck("DB-PG-HBA-TRUST", _PG, "В pg_hba.conf есть сетевой вход без пароля (trust)",
            _S.HIGH, "Замените метод trust для сетевых правил (host/hostssl) на "
            "scram-sha-256 и перечитайте конфигурацию (SELECT pg_reload_conf()).",
            "CIS PostgreSQL: подключения и вход", ("hba",),
            _pg_hba_methods({"trust"})),
    DbCheck("DB-PG-HBA-WEAK", _PG,
            "В pg_hba.conf есть сетевой вход по паролю открытым текстом или md5",
            _S.MEDIUM, "Используйте метод scram-sha-256 вместо password и md5 "
            "(после перевода паролей на SCRAM).",
            "CIS PostgreSQL: подключения и вход", ("hba",),
            _pg_hba_methods({"password", "md5"})),
    DbCheck("DB-PG-SUPERUSER", _PG,
            "Кроме postgres, есть суперпользователи PostgreSQL с правом входа",
            _S.MEDIUM, "Оставьте права суперпользователя только служебной учётной "
            "записи; прикладным ролям выдайте минимальные права (ALTER ROLE … "
            "NOSUPERUSER).", "CIS PostgreSQL: права доступа", ("roles",), _pg_superusers),
    DbCheck("DB-PG-PUBLIC-CREATE", _PG,
            "Любой пользователь может создавать объекты в схеме public",
            _S.LOW, "Выполните REVOKE CREATE ON SCHEMA public FROM PUBLIC в каждой базе "
            "(в PostgreSQL 15+ так по умолчанию).", "CIS PostgreSQL: права доступа",
            ("public_create",), _pg_public_create),
    DbCheck("DB-PG-LOGCONN", _PG, "Не журналируются подключения (log_connections = off)",
            _S.LOW, "Установите log_connections = on.",
            "CIS PostgreSQL: журналирование и аудит", ("settings",),
            _setting("log_connections", lambda v: not _on(v))),
    DbCheck("DB-PG-LOGDISCONN", _PG,
            "Не журналируются отключения (log_disconnections = off)", _S.LOW,
            "Установите log_disconnections = on.",
            "CIS PostgreSQL: журналирование и аудит", ("settings",),
            _setting("log_disconnections", lambda v: not _on(v))),
    DbCheck("DB-PG-LOGSTMT", _PG,
            "Не журналируются изменения структуры БД (log_statement = none)", _S.LOW,
            "Установите log_statement = ddl (или mod).",
            "CIS PostgreSQL: журналирование и аудит", ("settings",), _pg_log_statement),
    DbCheck("DB-PG-PGAUDIT", _PG, "Не подключено расширение аудита pgaudit", _S.LOW,
            "Добавьте pgaudit в shared_preload_libraries, создайте расширение и "
            "задайте pgaudit.log (например, ddl, role).",
            "CIS PostgreSQL: журналирование и аудит", ("settings",), _pg_pgaudit),
    # MySQL / MariaDB
    DbCheck("DB-MY-EMPTYPW", _MY, "Есть учётные записи MySQL/MariaDB без пароля",
            _S.HIGH, "Задайте пароли (ALTER USER … IDENTIFIED BY …) или удалите "
            "неиспользуемые учётные записи.", "CIS MySQL/MariaDB: аутентификация",
            ("users",), _my_empty_passwords),
    DbCheck("DB-MY-ANON", _MY, "Есть анонимные учётные записи MySQL/MariaDB", _S.HIGH,
            "Удалите анонимные учётные записи: DROP USER ''@'хост' "
            "(mysql_secure_installation).", "CIS MySQL/MariaDB: аутентификация",
            ("users",), _my_anonymous),
    DbCheck("DB-MY-REMOTEROOT", _MY, "Учётная запись root доступна по сети", _S.MEDIUM,
            "Оставьте root только для localhost; для удалённого администрирования "
            "заведите именные учётные записи.", "CIS MySQL/MariaDB: аутентификация",
            ("users",), _my_remote_root),
    DbCheck("DB-MY-LOCALINFILE", _MY, "Разрешена загрузка локальных файлов (local_infile)",
            _S.MEDIUM, "Установите local_infile = OFF в конфигурации сервера.",
            "CIS MySQL/MariaDB: общие настройки", ("settings",),
            _setting("local_infile", _on)),
    DbCheck("DB-MY-SECUREFILE", _MY,
            "Не ограничен каталог для чтения/записи файлов (secure_file_priv пуст)",
            _S.MEDIUM, "Задайте secure_file_priv отдельным каталогом или NULL "
            "(запрет LOAD DATA/SELECT … INTO OUTFILE).",
            "CIS MySQL/MariaDB: общие настройки", ("settings",),
            _setting("secure_file_priv", lambda v: v.strip() == "")),
    DbCheck("DB-MY-TLS", _MY, "Сервер допускает подключения без TLS "
            "(require_secure_transport = OFF)", _S.MEDIUM,
            "Настройте сертификат сервера и установите require_secure_transport = ON.",
            "CIS MySQL/MariaDB: шифрование", ("settings",), _my_secure_transport),
    DbCheck("DB-MY-NAMERES", _MY, "Включено разрешение имён клиентов (skip_name_resolve = OFF)",
            _S.LOW, "Установите skip_name_resolve = ON и используйте IP в учётных "
            "записях.", "CIS MySQL/MariaDB: общие настройки", ("settings",),
            _setting("skip_name_resolve", lambda v: not _on(v))),
    DbCheck("DB-MY-STRICT", _MY, "Не включён строгий режим SQL (sql_mode без STRICT_*)",
            _S.LOW, "Добавьте STRICT_ALL_TABLES или STRICT_TRANS_TABLES в sql_mode.",
            "CIS MySQL/MariaDB: общие настройки", ("settings",), _my_strict_mode),
    DbCheck("DB-MY-PWLIFE", _MY, "Не ограничен срок действия паролей "
            "(default_password_lifetime = 0 или больше 365)", _S.LOW,
            "Установите default_password_lifetime не больше 365 дней.",
            "CIS MySQL/MariaDB: аутентификация", ("settings",), _my_password_lifetime),
    DbCheck("DB-MY-LOGERR", _MY, "Не задан журнал ошибок (log_error пуст)", _S.LOW,
            "Задайте log_error — путь к журналу ошибок сервера.",
            "CIS MySQL/MariaDB: журналирование", ("settings",),
            _setting("log_error", lambda v: v.strip() == "")),
    DbCheck("DB-MY-TESTDB", _MY, "Существует тестовая база test", _S.LOW,
            "Удалите базу test: DROP DATABASE test.", "CIS MySQL/MariaDB: общие настройки",
            ("databases",), _my_test_db),
    # MS SQL Server
    DbCheck("DB-MS-XPCMD", _MS, "Включена процедура xp_cmdshell", _S.HIGH,
            "Отключите: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("xp_cmdshell")),
    DbCheck("DB-MS-ADHOC", _MS, "Включены распределённые запросы Ad Hoc", _S.MEDIUM,
            "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("ad hoc distributed queries")),
    DbCheck("DB-MS-CLR", _MS, "Включена среда CLR (clr enabled)", _S.MEDIUM,
            "EXEC sp_configure 'clr enabled', 0; RECONFIGURE (если сборки CLR не нужны).",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("clr enabled")),
    DbCheck("DB-MS-OLE", _MS, "Включены процедуры OLE Automation", _S.MEDIUM,
            "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("ole automation procedures")),
    DbCheck("DB-MS-XDBCHAIN", _MS, "Включена межбазовая цепочка владения", _S.MEDIUM,
            "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("cross db ownership chaining")),
    DbCheck("DB-MS-REMOTEACCESS", _MS, "Включён параметр remote access", _S.LOW,
            "EXEC sp_configure 'remote access', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("remote access")),
    DbCheck("DB-MS-DAC", _MS, "Выделенное административное подключение доступно по сети",
            _S.LOW, "EXEC sp_configure 'remote admin connections', 0; RECONFIGURE "
            "(кроме кластерных установок).",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("remote admin connections")),
    DbCheck("DB-MS-STARTUPPROCS", _MS, "Включён автозапуск процедур при старте",
            _S.LOW, "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE.",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("scan for startup procs")),
    DbCheck("DB-MS-DBMAIL", _MS, "Включён Database Mail", _S.LOW,
            "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE (если почта не нужна).",
            "CIS SQL Server: сокращение поверхности атаки", ("settings",),
            _ms_option("database mail xps")),
    DbCheck("DB-MS-SA", _MS, "Учётная запись sa включена", _S.MEDIUM,
            "Отключите: ALTER LOGIN [sa] DISABLE.", "CIS SQL Server: аутентификация",
            ("logins",), _ms_sa),
    DbCheck("DB-MS-SANAME", _MS, "Учётная запись sa не переименована", _S.LOW,
            "Переименуйте: ALTER LOGIN [sa] WITH NAME = [новое_имя].",
            "CIS SQL Server: аутентификация", ("logins",), _ms_sa_renamed),
    DbCheck("DB-MS-POLICY", _MS, "SQL-логины без проверки парольной политики Windows",
            _S.MEDIUM, "ALTER LOGIN [имя] WITH CHECK_POLICY = ON.",
            "CIS SQL Server: парольные политики", ("logins",),
            _ms_policy(3, "CHECK_POLICY")),
    DbCheck("DB-MS-EXPIRATION", _MS, "SQL-логины без срока действия пароля", _S.LOW,
            "ALTER LOGIN [имя] WITH CHECK_EXPIRATION = ON.",
            "CIS SQL Server: парольные политики", ("logins",),
            _ms_policy(4, "CHECK_EXPIRATION")),
    DbCheck("DB-MS-MIXED", _MS, "Включена смешанная проверка подлинности "
            "(SQL Server и Windows)", _S.LOW,
            "По возможности переведите сервер на проверку подлинности только Windows.",
            "CIS SQL Server: аутентификация", ("version",), _ms_mixed_mode),
    # Oracle
    DbCheck("DB-ORA-REMOTEOS", _ORA, "Включена удалённая аутентификация ОС "
            "(remote_os_authent)", _S.HIGH,
            "ALTER SYSTEM SET remote_os_authent = FALSE SCOPE = SPFILE; перезапуск.",
            "CIS Oracle Database: параметры экземпляра", ("settings",),
            _ora_param("remote_os_authent", _on)),
    DbCheck("DB-ORA-REMOTEROLES", _ORA, "Включены роли удалённой ОС (remote_os_roles)",
            _S.HIGH, "ALTER SYSTEM SET remote_os_roles = FALSE SCOPE = SPFILE; перезапуск.",
            "CIS Oracle Database: параметры экземпляра", ("settings",),
            _ora_param("remote_os_roles", _on)),
    DbCheck("DB-ORA-O7DICT", _ORA, "Открыт доступ к словарю данных (O7_DICTIONARY_ACCESSIBILITY)",
            _S.HIGH, "ALTER SYSTEM SET O7_DICTIONARY_ACCESSIBILITY = FALSE SCOPE = SPFILE.",
            "CIS Oracle Database: параметры экземпляра", ("settings",),
            _ora_param("o7_dictionary_accessibility", _on)),
    DbCheck("DB-ORA-AUDIT", _ORA, "Отключён журнал аудита (audit_trail = NONE)",
            _S.MEDIUM, "ALTER SYSTEM SET audit_trail = DB, EXTENDED SCOPE = SPFILE "
            "(или используйте Unified Auditing).",
            "CIS Oracle Database: аудит", ("settings",),
            _ora_param("audit_trail", lambda v: v.strip().upper() in ("NONE", "FALSE"))),
    DbCheck("DB-ORA-SQL92", _ORA, "Отключена проверка прав SQL92 (sql92_security = FALSE)",
            _S.LOW, "ALTER SYSTEM SET sql92_security = TRUE SCOPE = SPFILE.",
            "CIS Oracle Database: параметры экземпляра", ("settings",),
            _ora_param("sql92_security", lambda v: not _on(v))),
    DbCheck("DB-ORA-FAILEDLOGIN", _ORA,
            "Не ограничено число неудачных входов (FAILED_LOGIN_ATTEMPTS = UNLIMITED)",
            _S.MEDIUM, "ALTER PROFILE … LIMIT FAILED_LOGIN_ATTEMPTS 5.",
            "CIS Oracle Database: профили пользователей", ("profiles",),
            _ora_profile_limit("FAILED_LOGIN_ATTEMPTS", _unlimited)),
    DbCheck("DB-ORA-PWLIFE", _ORA,
            "Не ограничен срок действия пароля (PASSWORD_LIFE_TIME = UNLIMITED)",
            _S.LOW, "ALTER PROFILE … LIMIT PASSWORD_LIFE_TIME 90.",
            "CIS Oracle Database: профили пользователей", ("profiles",),
            _ora_profile_limit("PASSWORD_LIFE_TIME", _unlimited)),
    DbCheck("DB-ORA-PWVERIFY", _ORA, "Не задана функция проверки сложности пароля",
            _S.MEDIUM, "ALTER PROFILE … LIMIT PASSWORD_VERIFY_FUNCTION "
            "ora12c_verify_function (или собственная).",
            "CIS Oracle Database: профили пользователей", ("profiles",),
            _ora_profile_limit("PASSWORD_VERIFY_FUNCTION",
                               lambda v: v in ("NULL", "", "UNLIMITED"))),
    DbCheck("DB-ORA-DEFPWD", _ORA, "Есть учётные записи с паролем по умолчанию", _S.HIGH,
            "Смените пароли или заблокируйте учётные записи (ALTER USER … ACCOUNT LOCK).",
            "CIS Oracle Database: учётные записи", ("default_pwd",), _ora_default_pwd),
    DbCheck("DB-ORA-PUBLICEXEC", _ORA, "Опасные пакеты PL/SQL доступны роли PUBLIC",
            _S.MEDIUM, "REVOKE EXECUTE ON <пакет> FROM PUBLIC и выдайте права только "
            "нужным схемам.", "CIS Oracle Database: права PUBLIC", ("public_exec",),
            _ora_public_exec),
)


def evaluate(facts: DbFacts) -> list[tuple[DbCheck, CheckResult]]:
    """Все правила протокола: (правило, результат). UNKNOWN — нет данных/прав."""
    out = []
    for check in CHECKS:
        if check.protocol != facts.protocol:
            continue
        if any(n not in facts.rows for n in check.needs):
            missing = next(n for n in check.needs if n not in facts.rows)
            out.append((check, CheckResult(UNKNOWN, facts.unavailable.get(missing, ""))))
            continue
        try:
            res = check.fn(facts)
        except Exception as e:  # noqa: BLE001 — непредвиденный формат вывода СУБД
            res = CheckResult(UNKNOWN, f"не удалось разобрать: {type(e).__name__}")
        out.append((check, res))
    return out
