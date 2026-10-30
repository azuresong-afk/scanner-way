"""Проверка парольной политики хоста — пассивная, БЕЗ подбора и БЕЗ сети.

Это не сетевая проверка входов (её делает `cred_audit`), а анализ НАСТРОЕК
парольной политики, уже собранных по учётной записи активов тем же
SSH-транспортом в рамках аудита конфигураций (config_audit, R1a). На вход —
содержимое конфигурационных файлов политики; хеши паролей (`/etc/shadow`) НЕ
анализируются и сюда не передаются — оценивается политика, а не содержимое.

Проверяются типовые для Linux параметры:
  * блокировка учётной записи после неудачных входов (pam_faillock / faillock.conf
    / устаревший pam_tally2) — есть ли и задан ли порог `deny`;
  * минимальная длина пароля (`minlen` pwquality / `PASS_MIN_LEN` login.defs);
  * требования к сложности (классы символов pwquality: `minclass` или кредиты
    `dcredit/ucredit/ocredit/lcredit`);
  * максимальный срок действия пароля (`PASS_MAX_DAYS`).

Результат — `Finding(finding_type=CONFIG)` с рекомендацией и ссылкой на документ
контроля. Так заказчик получает оценку парольной политики даже там, где сетевая
проверка входов не согласована.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.core.models import Finding, FindingType, Severity
from scanner.modules.base import ScanContext, ScanModule

# Имена файлов, содержимое которых анализируется (любые из них могут отсутствовать).
LOGIN_DEFS = "/etc/login.defs"
PWQUALITY = "/etc/security/pwquality.conf"
FAILLOCK = "/etc/security/faillock.conf"
# PAM-стек, где может подключаться pam_faillock/pam_pwquality/pam_tally2.
PAM_PASSWORD = "/etc/pam.d/common-password"
PAM_AUTH = "/etc/pam.d/common-auth"
PAM_SYSTEM_AUTH = "/etc/pam.d/system-auth"
# Всё, что config_audit читает с хоста для этой проверки (и только это).
POLICY_FILES = (LOGIN_DEFS, PWQUALITY, FAILLOCK, PAM_PASSWORD, PAM_AUTH, PAM_SYSTEM_AUTH)

# Рекомендуемый минимум длины пароля (типовой; не норматив договора).
MIN_PASSWORD_LENGTH = 8

_CONTROL_DOCS = {
    "lockout": "https://man7.org/linux/man-pages/man5/faillock.conf.5.html",
    "min-length": "https://man7.org/linux/man-pages/man5/pwquality.conf.5.html",
    "complexity": "https://man7.org/linux/man-pages/man5/pwquality.conf.5.html",
    "max-age": "https://man7.org/linux/man-pages/man5/login.defs.5.html",
}


def _login_defs(text: str) -> dict[str, str]:
    """`KEY value` без комментариев -> {KEY: value} (последнее значение)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].upper()] = parts[1].strip()
    return out


def _kv_conf(text: str) -> dict[str, str]:
    """`key = value` (pwquality/faillock) без комментариев -> {key: value}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().lower()] = value.strip()
    return out


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    m = re.search(r"-?\d+", value)
    return int(m.group()) if m else None


@dataclass(slots=True)
class PolicyFinding:
    key: str
    severity: Severity
    title: str
    evidence: str


def _lockout_configured(configs: dict[str, str]) -> bool:
    """Есть ли блокировка учётки после неудачных входов (с ненулевым порогом)."""
    faillock = _kv_conf(configs.get(FAILLOCK, ""))
    deny = _int(faillock.get("deny"))
    if deny is not None and deny > 0:
        return True
    pam = " ".join(configs.get(f, "") for f in (PAM_PASSWORD, PAM_AUTH, PAM_SYSTEM_AUTH))
    if "pam_faillock" in pam or "pam_tally2" in pam:
        m = re.search(r"deny\s*=\s*(\d+)", pam)
        # модуль подключён; порог deny>0 либо задаётся в faillock.conf (без него
        # pam_faillock блокировку не включит) — считаем настроенным, если deny>0
        if m and int(m.group(1)) > 0:
            return True
        if "pam_tally2" in pam and m and int(m.group(1)) > 0:
            return True
    return False


def analyze_policy(host: str, configs: dict[str, str]) -> list[Finding]:
    """Находки парольной политики по собранной конфигурации одного хоста."""
    results: list[PolicyFinding] = []

    if not _lockout_configured(configs):
        results.append(PolicyFinding(
            "lockout", Severity.MEDIUM,
            "Не настроена блокировка учётной записи после неудачных входов",
            "В собранной конфигурации (faillock.conf / PAM) не найдено правило "
            "блокировки учётки с ненулевым порогом (deny). Без него возможен "
            "неограниченный подбор пароля по сети."))

    pwq = _kv_conf(configs.get(PWQUALITY, ""))
    defs = _login_defs(configs.get(LOGIN_DEFS, ""))
    minlen = _int(pwq.get("minlen"))
    if minlen is None:
        minlen = _int(defs.get("PASS_MIN_LEN"))
    if minlen is None:
        results.append(PolicyFinding(
            "min-length", Severity.MEDIUM,
            "Не задана минимальная длина пароля",
            "Ни pwquality (minlen), ни login.defs (PASS_MIN_LEN) не задают "
            "минимальную длину пароля."))
    elif minlen < MIN_PASSWORD_LENGTH:
        results.append(PolicyFinding(
            "min-length", Severity.MEDIUM,
            f"Минимальная длина пароля ниже рекомендуемой ({minlen} < "
            f"{MIN_PASSWORD_LENGTH})",
            f"Минимальная длина пароля = {minlen}; рекомендуется не менее "
            f"{MIN_PASSWORD_LENGTH} символов."))

    minclass = _int(pwq.get("minclass"))
    credits = [pwq.get(k) for k in ("dcredit", "ucredit", "ocredit", "lcredit")]
    has_complexity = (minclass is not None and minclass >= 2) or any(
        (_int(c) or 0) < 0 for c in credits)
    if not has_complexity:
        results.append(PolicyFinding(
            "complexity", Severity.LOW,
            "Не заданы требования к сложности пароля",
            "pwquality не требует нескольких классов символов (minclass) и не "
            "задаёт кредиты сложности (dcredit/ucredit/ocredit/lcredit)."))

    max_days = _int(defs.get("PASS_MAX_DAYS"))
    if max_days is not None and max_days > 365:
        results.append(PolicyFinding(
            "max-age", Severity.LOW,
            f"Срок действия пароля чрезмерно велик (PASS_MAX_DAYS={max_days})",
            f"PASS_MAX_DAYS={max_days}; пароль не требует смены более года."))

    return [_to_finding(host, r) for r in results]


def _to_finding(host: str, r: PolicyFinding) -> Finding:
    doc = _CONTROL_DOCS.get(r.key)
    evidence = r.evidence + (f" Документ контроля: {doc}" if doc else "")
    return Finding(
        module=PasswordPolicyModule.name, host=host, port=None,
        finding_type=FindingType.CONFIG, severity=r.severity,
        title=r.title, vuln_id=f"POLICY:password-{r.key}", evidence=evidence)


class PasswordPolicyModule(ScanModule):
    """Оценка парольной политики по конфигурации, собранной config_audit (R1a).

    Инертен без данных: если конфигурация политики не собрана
    (`ctx.host_policy_configs` пуст), пишет осознанный пропуск и ничего не
    возвращает — ни одной сетевой операции."""

    name = "password_policy"

    def run(self, ctx: ScanContext) -> list[Finding]:
        configs = ctx.host_policy_configs or {}
        if not configs:
            ctx.audit.record(subject="scanner", action="password_policy_skip",
                             target=",".join(sorted(ctx.targets)) or "-",
                             result="no_policy_data")
            return []
        findings: list[Finding] = []
        for host in sorted(configs):
            host_findings = analyze_policy(host, configs[host])
            findings.extend(host_findings)
            ctx.audit.record(subject="scanner", action="password_policy_eval",
                             target=host, result="ok",
                             details={"findings": len(host_findings),
                                      "files": sorted(configs[host])})
        return findings
