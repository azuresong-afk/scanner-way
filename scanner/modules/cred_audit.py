"""Модуль 4: аудит учётных данных (контролируемый).

Назначение — выявить ОЧЕВИДНО слабые/дефолтные учётные записи на АВТОРИЗОВАННЫХ
хостах, строго по согласованию с заказчиком, как это делает credential check в
OpenVAS/Nessus. Это проверка гигиены паролей, а НЕ инструмент взлома.

Встроенные гарантии безопасности (defense in depth):
  * работает только по целям из allowlist — хост пробы должен входить в
    `ctx.targets` и быть литеральным IP; всё остальное отклоняется с записью в
    аудит и без единой попытки подключения;
  * БЕЗ встроенных словарей — набор проверяемых учёток задаёт оператор осознанно
    (`CredentialAuditOptions.credentials` / `service_credentials`); если набор не
    задан, модуль не делает ни одной попытки;
  * БЕЗ встроенного бэкенда аутентификации — если оператор не подключил
    `Authenticator`, модуль инертен (ноль попыток). Реальные протокольные клиенты
    сюда не зашиты, поэтому по умолчанию модуль ничего не атакует;
  * жёсткий потолок попыток на хост (`ctx.rate.max_auth_attempts_per_target`) и
    отдельный, более строгий лимит попыток на одну учётную запись
    (`max_attempts_per_account`) — защита от блокировки аккаунтов;
  * экспоненциальная пауза (backoff) между попытками, чтобы не спровоцировать
    rate-based блокировку/DoS;
  * немедленная остановка по хосту при признаке блокировки (lockout), сигнале
    «слишком много попыток» или серии ошибок соединения;
  * каждая попытка пишется в `ctx.audit`; пароль в журнал НЕ попадает — пишется
    только логин и необратимый отпечаток секрета.

Модуль включается ТОЛЬКО явным правом `cred_audit` (проверка права — на уровне
API/оркестратора, T7); он не входит ни в одну роль по умолчанию и не участвует ни
в какой автоматической оркестрации.
"""
from __future__ import annotations

import enum
import hashlib
import ipaddress
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from scanner.compliance.facts import record as record_fact
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.modules.base import ScanContext, ScanModule

# Сервисы с аутентификацией, которые имеет смысл проверять на слабые учётки.
# Используется только для отбора проб из discovery; порт берётся из ServiceInfo.
SUPPORTED_SERVICES: frozenset[str] = frozenset({
    "ssh", "rdp", "ms-wbt-server", "smb", "microsoft-ds", "netbios-ssn",
    "ftp", "telnet", "vnc", "redis", "mysql", "postgres", "postgresql",
    "mssql", "ms-sql-s", "mongodb", "ldap", "winrm",
})

# Учётки и имена, для которых слабый/дефолтный пароль особенно критичен.
_ADMIN_USERS: frozenset[str] = frozenset({
    "root", "admin", "administrator", "sa", "postgres", "oracle",
})


class AuthOutcome(enum.StrEnum):
    SUCCESS = "success"          # учётка подошла — это находка слабой учётки
    FAILURE = "failure"          # отклонено — штатный результат
    LOCKOUT = "lockout"          # цель сигналит блокировку/«too many attempts» → СТОП
    ERROR = "error"              # ошибка соединения/протокола
    UNSUPPORTED = "unsupported"  # для сервиса нет бэкенда аутентификации


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Итог одной попытки. `detail` — НЕсекретный текст для аудита/находки."""
    outcome: AuthOutcome
    detail: str | None = None


class Authenticator(Protocol):
    """Бэкенд проверки одной учётки на одном сервисе.

    Реализацию (реальные протокольные клиенты) подключает оператор осознанно; в
    поставке модуля её нет. В тестах подменяется фейком. Реализация обязана
    возвращать `AuthOutcome.LOCKOUT`, если цель сообщила о блокировке учётной
    записи или о превышении числа попыток, — модуль по этому сигналу немедленно
    прекращает работу по хосту.
    """

    def authenticate(self, host: str, port: int, service: str,
                     credential: Credential, timeout: float) -> AuthResult: ...


def _fingerprint(secret: str) -> str:
    """Короткий необратимый-на-вид отпечаток секрета для КОРРЕЛЯЦИИ в аудите.

    Это НЕ защита секрета (хеш слабого пароля тривиально обратим перебором) —
    это способ связать попытки в журнале, не печатая сам пароль открытым текстом.
    """
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


@dataclass(frozen=True, slots=True)
class Credential:
    """Учётка из набора ОПЕРАТОРА. Пароль не логируется и не хранится в репре."""
    username: str
    secret: str = ""  # допускается пустой — проверка пустого пароля

    def __post_init__(self) -> None:
        if not self.username or any(c in self.username for c in "\x00\r\n"):
            raise ValueError("username: пустой или содержит управляющие символы")
        if any(c in self.secret for c in "\x00\r\n"):
            raise ValueError("secret: содержит управляющие символы")

    @property
    def secret_id(self) -> str:
        return _fingerprint(self.secret)

    def masked(self) -> str:
        tag = "<пустой>" if self.secret == "" else f"#{self.secret_id}"
        return f"{self.username}:{tag}"

    def __repr__(self) -> str:  # секрет никогда не выводится целиком
        return f"Credential(username={self.username!r}, secret=***{self.secret_id})"


@dataclass(frozen=True, slots=True)
class Probe:
    """Что проверяем: хост, порт, имя сервиса (нормализованное)."""
    host: str
    port: int
    service: str


@dataclass(slots=True)
class CredentialAuditOptions:
    # Набор учёток оператора. Применяется ко всем поддерживаемым сервисам.
    credentials: list[Credential] = field(default_factory=list)
    # Уточнение набора по сервису (например, доменные учётки только для smb).
    service_credentials: dict[str, list[Credential]] = field(default_factory=dict)
    # Явный список проб; если None — пробы берутся из ctx.services (discovery).
    probes: list[Probe] | None = None
    # Отдельный, более строгий лимит на одну учётную запись (анти-lockout).
    max_attempts_per_account: int = 3
    # Серия подряд ошибок соединения, после которой хост прекращается.
    max_consecutive_errors: int = 5
    # Потолок паузы backoff.
    max_backoff_sec: float = 30.0
    connect_timeout_sec: float = 10.0
    # Ограничение набора сервисов (по умолчанию — все поддерживаемые).
    services: frozenset[str] = SUPPORTED_SERVICES


def validate_targets(targets: Sequence[str]) -> tuple[set[str], list[str]]:
    """Делит цели на (валидные IP, отклонённые). Имена и подсети — отклоняются."""
    ok: set[str] = set()
    rejected: list[str] = []
    for t in targets:
        try:
            ok.add(str(ipaddress.ip_address(t.strip())))
        except ValueError:
            rejected.append(t)
    return ok, rejected


def _severity_for(cred: Credential) -> Severity:
    """Пустой пароль или административная учётка — критично; иначе высокий риск."""
    if cred.secret == "" or cred.username.lower() in _ADMIN_USERS:
        return Severity.CRITICAL
    return Severity.HIGH


def probes_from_services(services: Iterable[ServiceInfo],
                         allowed: set[str],
                         wanted: frozenset[str]) -> list[Probe]:
    """Строит пробы из вывода discovery, оставляя только allowlist-хосты и
    поддерживаемые сервисы. Дубли (host, port) убираются."""
    seen: set[tuple[str, int]] = set()
    probes: list[Probe] = []
    for s in services:
        name = (s.service or "").lower()
        if s.host not in allowed or name not in wanted:
            continue
        key = (s.host, s.port)
        if key in seen:
            continue
        seen.add(key)
        probes.append(Probe(host=s.host, port=s.port, service=name))
    return probes


class _Backoff:
    """Экспоненциальная пауза между попытками в пределах одного хоста.

    Перед первой попыткой паузы нет; перед n-й (n>=2) пауза равна
    base * factor**(n-2), но не больше max_sec. Сбрасывается на каждый хост.
    """

    def __init__(self, base: float, factor: float, max_sec: float,
                 sleep: Callable[[float], None]):
        self.base = max(0.0, base)
        self.factor = max(1.0, factor)
        self.max_sec = max_sec
        self._sleep = sleep
        self._n = 0

    def wait(self) -> float:
        delay = 0.0
        if self._n > 0:
            delay = min(self.base * (self.factor ** (self._n - 1)), self.max_sec)
            if delay > 0:
                self._sleep(delay)
        self._n += 1
        return delay


class CredentialAuditModule(ScanModule):
    name = "cred_audit"

    def __init__(self, options: CredentialAuditOptions | None = None,
                 authenticator: Authenticator | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.options = options or CredentialAuditOptions()
        self._auth = authenticator
        self._sleep = sleep

    # --- отбор учёток под сервис -------------------------------------------------

    def _candidates_from_ctx(self, ctx: ScanContext) -> list[Credential]:
        """Пары (логин, секрет) из набора проверки, переданные оркестратором.

        Применяются ТОЛЬКО если оператор не задал набор в опциях модуля явно.
        Некорректные записи пропускаются с записью в аудит — набор целиком не
        роняет прогон."""
        out: list[Credential] = []
        for username, secret in ctx.cred_candidates:
            try:
                out.append(Credential(username, secret))
            except ValueError as e:
                ctx.audit.record(subject="scanner", action="cred_audit_skip",
                                 target="-", result="invalid_candidate",
                                 details={"reason": str(e)[:200]})
        return out

    def _base_credentials(self, ctx: ScanContext) -> list[Credential]:
        """Набор оператора из опций; если он пуст — кандидаты из ctx.cred_candidates."""
        if self.options.credentials:
            return list(self.options.credentials)
        return self._candidates_from_ctx(ctx)

    def _creds_for(self, service: str, base: Sequence[Credential]) -> list[Credential]:
        combined = list(base)
        combined += self.options.service_credentials.get(service, [])
        out: list[Credential] = []
        seen: set[tuple[str, str]] = set()
        for c in combined:
            k = (c.username, c.secret)
            if k not in seen:
                seen.add(k)
                out.append(c)
        return out

    def _probes(self, ctx: ScanContext, allowed: set[str]) -> tuple[list[Probe], list[str]]:
        """Возвращает (валидные пробы в allowlist, отклонённые цели проб)."""
        if self.options.probes is not None:
            valid, rejected = [], []
            for p in self.options.probes:
                (valid if p.host in allowed else rejected).append(p)
            return valid, [p.host for p in rejected]
        services = ctx.services or []
        return probes_from_services(services, allowed, self.options.services), []

    # --- основной проход ---------------------------------------------------------

    def run(self, ctx: ScanContext) -> list[Finding]:
        allowed, rejected = validate_targets(ctx.targets)
        for t in rejected:
            ctx.audit.record(subject="scanner", action="cred_audit_deny",
                             target=t, result="not_an_ip_literal")

        # Набор учёток: либо задан оператором в опциях, либо передан оркестратором
        # из согласованного набора проверки (ctx.cred_candidates). Нет ни того, ни
        # другого — модуль не делает ни одной попытки (осознанный пропуск в аудите).
        base_creds = self._base_credentials(ctx)
        if not base_creds and not self.options.service_credentials:
            ctx.audit.record(subject="scanner", action="cred_audit_skip",
                             target=",".join(sorted(allowed)) or "-",
                             result="no_credentials")
            return []

        # Без подключённого бэкенда аутентификации модуль инертен (ноль попыток).
        if self._auth is None:
            ctx.audit.record(subject="scanner", action="cred_audit_skip",
                             target=",".join(sorted(allowed)) or "-",
                             result="no_authenticator")
            return []

        probes, denied = self._probes(ctx, allowed)
        for h in denied:
            ctx.audit.record(subject="scanner", action="cred_audit_deny",
                             target=h, result="target_not_in_allowlist")

        cap = max(0, ctx.rate.max_auth_attempts_per_target)
        acct_cap = max(1, min(self.options.max_attempts_per_account, cap or 1))

        findings: list[Finding] = []
        by_host: dict[str, list[Probe]] = {}
        for p in probes:
            by_host.setdefault(p.host, []).append(p)

        for host, host_probes in by_host.items():
            findings += self._run_host(ctx, host, host_probes, cap, acct_cap, base_creds)
        return findings

    def _run_host(self, ctx: ScanContext, host: str, probes: list[Probe],
                  cap: int, acct_cap: int, base_creds: Sequence[Credential]) -> list[Finding]:
        findings: list[Finding] = []
        attempts = 0
        per_account: Counter[str] = Counter()
        consecutive_errors = 0
        backoff = _Backoff(ctx.rate.delay_between_attempts_sec,
                           ctx.rate.backoff_factor,
                           self.options.max_backoff_sec, self._sleep)

        for probe in probes:
            creds = self._creds_for(probe.service, base_creds)
            if not creds:
                ctx.audit.record(subject="scanner", action="cred_audit_skip",
                                 target=f"{host}:{probe.port}/{probe.service}",
                                 result="no_credentials_for_service")
                continue
            for cred in creds:
                tgt = f"{host}:{probe.port}/{probe.service}"
                if cap and attempts >= cap:
                    ctx.audit.record(subject="scanner", action="cred_audit_limit",
                                     target=host, result="max_attempts_reached",
                                     details={"attempts": attempts, "cap": cap})
                    return findings  # хост исчерпал общий лимит
                if per_account[cred.username] >= acct_cap:
                    ctx.audit.record(subject="scanner", action="cred_audit_skip",
                                     target=tgt, result="account_limit_reached",
                                     details={"user": cred.username, "cap": acct_cap})
                    continue

                backoff.wait()  # экспоненциальная пауза перед попыткой (анти-lockout)
                try:
                    res = self._auth.authenticate(  # type: ignore[union-attr]
                        host, probe.port, probe.service, cred,
                        self.options.connect_timeout_sec)
                except Exception as e:  # noqa: BLE001 — бэкенд оператора не должен ронять прогон
                    res = AuthResult(AuthOutcome.ERROR, f"{type(e).__name__}: {e}"[:200])

                attempts += 1
                per_account[cred.username] += 1
                if res.outcome in (AuthOutcome.SUCCESS, AuthOutcome.FAILURE):
                    # для профилей соответствия (R5): вход на хосте реально проверен
                    record_fact(ctx.compliance_facts, host, "cred_audit", True)
                ctx.audit.record(
                    subject="scanner", action="cred_audit_attempt", target=tgt,
                    result=str(res.outcome),
                    details={"user": cred.username, "secret_id": cred.secret_id,
                             "detail": res.detail})

                if res.outcome is AuthOutcome.SUCCESS:
                    consecutive_errors = 0
                    findings.append(self._weak_cred_finding(host, probe, cred, res))
                elif res.outcome is AuthOutcome.LOCKOUT:
                    ctx.audit.record(subject="scanner", action="cred_audit_lockout",
                                     target=host, result="stopped",
                                     details={"service": probe.service,
                                              "user": cred.username})
                    findings.append(Finding(
                        module=self.name, host=host, port=probe.port,
                        finding_type=FindingType.INFO, severity=Severity.INFO,
                        title=f"Проверка учётных данных остановлена: блокировка на {host}",
                        vuln_id="INFO:cred-audit-lockout",
                        evidence=f"Цель сообщила о блокировке/лимите попыток на "
                                 f"{probe.service}; дальнейшие проверки по {host} прекращены."))
                    return findings  # немедленный стоп по хосту
                elif res.outcome is AuthOutcome.ERROR:
                    consecutive_errors += 1
                    if consecutive_errors >= self.options.max_consecutive_errors:
                        ctx.audit.record(subject="scanner", action="cred_audit_stop",
                                         target=host, result="too_many_errors",
                                         details={"consecutive_errors": consecutive_errors})
                        findings.append(Finding(
                            module=self.name, host=host, port=probe.port,
                            finding_type=FindingType.INFO, severity=Severity.INFO,
                            title=f"Проверка учётных данных остановлена: серия ошибок на {host}",
                            vuln_id="INFO:cred-audit-errors",
                            evidence=f"{consecutive_errors} ошибок соединения подряд; "
                                     f"дальнейшие проверки по {host} прекращены."))
                        return findings
                else:  # FAILURE / UNSUPPORTED
                    consecutive_errors = 0
                    if res.outcome is AuthOutcome.UNSUPPORTED:
                        break  # для этого сервиса бэкенда нет — следующая проба
        return findings

    def _weak_cred_finding(self, host: str, probe: Probe, cred: Credential,
                           res: AuthResult) -> Finding:
        detail = f" {res.detail}" if res.detail else ""
        return Finding(
            module=self.name, host=host, port=probe.port,
            finding_type=FindingType.CRED, severity=_severity_for(cred),
            title=f"Слабые/дефолтные учётные данные: {probe.service} ({cred.username})",
            vuln_id=f"CRED:{probe.service}/{cred.username}",
            evidence=f"Успешная аутентификация на {host}:{probe.port}/{probe.service} "
                     f"с учёткой из набора оператора {cred.masked()} "
                     f"(пароль в журнал не пишется).{detail}")
