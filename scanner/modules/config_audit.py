"""Модуль 3: аудит конфигураций — БЕЗАГЕНТНЫЙ (бэкенды: OpenSCAP, Lynis).

Профили: CIS Benchmarks и, для гос-контекста, требования ФСТЭК/ГОСТ (любой
XCCDF/SCAP datastream, переданный оператором).

Только безагентный режим (решение заказчика): на цели ничего не остаётся.
Каждая проверка — одно SSH-подключение, в котором:
  * OpenSCAP — datastream со сканера передаётся через stdin во временный
    каталог (mktemp), там же запускается `oscap xccdf eval`, результаты XCCDF
    возвращаются сжатыми в stdout. Это то же, что делает `oscap-ssh`, но без
    зависимости от openscap-utils на сканере. На цели нужен пакет
    openscap-scanner (сам движок), постоянного агента нет;
  * Lynis — архив Lynis со сканера распаковывается во временный каталог,
    запускается `lynis audit system --usecwd`, забирается report.dat.
В обоих случаях временный каталог удаляется `trap ... EXIT` даже при ошибке.

Безопасность:
- цели приходят уже отфильтрованными allowlist-ом; модуль дополнительно
  принимает только литеральные IP (как discovery) — отказ пишется в аудит;
- SSH-доступы — параметры engagement (`SshCredentials`): только ключ, без
  паролей (пароль попал бы в argv/окружение). Путь к ключу и прочие секреты
  НЕ пишутся в аудит — только логин, порт и способ аутентификации;
- `BatchMode=yes` (никаких интерактивных запросов), `sudo -n` (без пароля);
- подключения ограничены RateProfile: не больше `max_concurrency` параллельных
  хостов и минимальный интервал между стартами подключений;
- вывод цели считается недоверенным: лимит размера, XML без DOCTYPE/ENTITY;
- каждое подключение (backend, хост, команда без секретов) и его итог — в
  ctx.audit.

Результат — `Finding(finding_type=CONFIG)`: `vuln_id` = id правила бенчмарка
(XCCDF rule id или `LYNIS:<TEST-ID>`), так что ключ сравнения прогонов
стабилен. Рекомендации по устранению собираются в `ConfigAuditModule.remediations`
(id правила -> текст) — это справочник `benchmark` для
`reporting.remediation.RemediationResolver`.
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import re
import shlex
import subprocess
import tarfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from scanner.core.models import Finding, FindingType, Severity
from scanner.core.ratelimit import RateProfile
from scanner.modules.base import ScanContext, ScanModule

OPENSCAP = "openscap"
LYNIS = "lynis"
BACKENDS = (OPENSCAP, LYNIS)

# Предел вывода с цели (сжатые результаты XCCDF полного SSG — единицы МБ).
MAX_OUTPUT_BYTES = 64 * 1024 * 1024

_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


class ConfigAuditError(RuntimeError):
    """Ошибка проверки одного хоста (подключение, движок, разбор вывода)."""


@dataclass(frozen=True, slots=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: str


# Раннер: (argv, stdin, timeout_sec) -> RunResult. Подменяется в тестах.
Runner = Callable[[list[str], bytes | None, float], RunResult]


@dataclass(frozen=True, slots=True)
class SshCredentials:
    """SSH-доступ к цели из параметров engagement. Только аутентификация ключом."""
    username: str
    key_path: str = field(repr=False)
    port: int = 22
    sudo: bool = True                  # `sudo -n`: нужен NOPASSWD для учётки аудита

    def __post_init__(self):
        if not _USER_RE.match(self.username):
            raise ValueError(f"недопустимое имя пользователя SSH: {self.username!r}")
        if not 0 < self.port < 65536:
            raise ValueError(f"недопустимый порт SSH: {self.port}")
        if not self.key_path or self.key_path.startswith("-"):
            raise ValueError("нужен путь к ключу SSH")

    def describe(self) -> dict[str, object]:
        """Описание для аудита — без пути к ключу и иных секретов."""
        return {"user": self.username, "port": self.port, "auth": "publickey",
                "sudo": self.sudo}


@dataclass(slots=True)
class ConfigAuditOptions:
    credentials: SshCredentials | None = None             # по умолчанию для всех целей
    host_credentials: Mapping[str, SshCredentials] = field(default_factory=dict)
    backends: Sequence[str] = BACKENDS
    # OpenSCAP: datastream и профиль (CIS / ФСТЭК / ГОСТ — что передал оператор)
    scap_content: str = "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml"
    scap_profile: str = "xccdf_org.ssgproject.content_profile_standard"
    # Lynis: готовый архив (официальный lynis-*.tar.gz с каталогом lynis/) или
    # сборка из установленного пакета Debian/Ubuntu.
    lynis_bundle: str | None = None
    lynis_script: str = "/usr/sbin/lynis"
    lynis_share_dir: str = "/usr/share/lynis"
    lynis_etc_dir: str = "/etc/lynis"
    # SSH
    ssh_path: str = "ssh"
    known_hosts_file: str | None = None
    strict_host_keys: bool = False      # False — accept-new (TOFU), True — только known_hosts
    connect_timeout_sec: int = 15
    command_timeout_sec: int = 1800
    max_parallel_hosts: int = 4         # верхняя граница; реальная — min с RateProfile


# --- SSH и удалённые сценарии ------------------------------------------------

def validate_targets(targets: Sequence[str]) -> tuple[list[str], list[str]]:
    """Делит цели на (валидные IP, отклонённые). Подсети и имена — отклоняются."""
    ok, rejected = [], []
    for t in targets:
        try:
            ok.append(str(ipaddress.ip_address(t.strip())))
        except ValueError:
            rejected.append(t)
    return ok, rejected


def build_ssh_command(host: str, creds: SshCredentials, remote_script: str,
                      opts: ConfigAuditOptions) -> list[str]:
    """argv ssh без shell на стороне сканера. host — уже проверенный IP."""
    cmd = [opts.ssh_path,
           "-o", "BatchMode=yes",
           "-o", "PasswordAuthentication=no",
           "-o", "KbdInteractiveAuthentication=no",
           "-o", "IdentitiesOnly=yes",
           "-o", f"ConnectTimeout={opts.connect_timeout_sec}",
           "-o", "ServerAliveInterval=30",
           "-o", "StrictHostKeyChecking=" + ("yes" if opts.strict_host_keys else "accept-new")]
    if opts.known_hosts_file:
        cmd += ["-o", f"UserKnownHostsFile={opts.known_hosts_file}"]
    cmd += ["-i", creds.key_path, "-p", str(creds.port), "-l", creds.username,
            "--", host, "sh -c " + shlex.quote(remote_script)]
    return cmd


def redact_command(cmd: Sequence[str], creds: SshCredentials) -> str:
    """Команда для аудита: путь к ключу заменён на ***, тело сценария сокращено."""
    out = []
    for i, part in enumerate(cmd):
        if i > 0 and cmd[i - 1] == "-i":
            out.append("***")
        elif part.startswith("sh -c "):
            out.append("sh -c <script>")
        else:
            out.append(part)
    return shlex.join(out)


def _sudo(creds: SshCredentials) -> str:
    return "sudo -n " if creds.sudo else ""


def openscap_script(profile: str, creds: SshCredentials) -> str:
    """Сценарий на цели: stdin = gzip(datastream), stdout = gzip(XCCDF results)."""
    if not _PROFILE_RE.match(profile):
        raise ValueError(f"недопустимый id профиля XCCDF: {profile!r}")
    s = _sudo(creds)
    return f"""set -eu
umask 077
command -v oscap >/dev/null 2>&1 || {{ echo 'oscap (openscap-scanner) not found on target' >&2; exit 127; }}
d=$(mktemp -d /tmp/scanner-cfg.XXXXXXXX)
trap '{s}rm -rf "$d"' EXIT
gzip -dc > "$d/ds.xml"
rc=0
{s}oscap xccdf eval --profile {shlex.quote(profile)} --results "$d/results.xml" "$d/ds.xml" </dev/null >/dev/null 2>"$d/err" || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then tail -c 2000 "$d/err" >&2; exit "$rc"; fi
{s}gzip -c "$d/results.xml"
"""


def lynis_script(creds: SshCredentials) -> str:
    """Сценарий на цели: stdin = tar.gz с каталогом lynis/, stdout = report.dat."""
    s = _sudo(creds)
    return f"""set -eu
umask 077
d=$(mktemp -d /tmp/scanner-cfg.XXXXXXXX)
trap '{s}rm -rf "$d"' EXIT
{s}tar -xzf - -C "$d"
cd "$d/lynis"
rc=0
{s}./lynis audit system --usecwd --quiet --no-colors --report-file "$d/report.dat" --logfile "$d/lynis.log" </dev/null >/dev/null 2>"$d/err" || rc=$?
if ! {s}test -s "$d/report.dat"; then
  tail -c 2000 "$d/err" >&2; [ "$rc" -ne 0 ] || rc=1; exit "$rc"
fi
{s}cat "$d/report.dat"
"""


def build_lynis_bundle(opts: ConfigAuditOptions) -> bytes:
    """tar.gz с каталогом lynis/ для запуска с --usecwd.

    Файлы получают владельца root и права 0644/0755: Lynis отказывается
    подключать include-файлы с иными правами или чужим владельцем.
    """
    if opts.lynis_bundle:
        return Path(opts.lynis_bundle).read_bytes()

    buf = io.BytesIO()

    def add(tar: tarfile.TarFile, src: Path, arc: str, mode: int) -> None:
        def norm(ti: tarfile.TarInfo) -> tarfile.TarInfo:
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mode = 0o755 if ti.isdir() else mode
            return ti
        tar.add(src, arcname=arc, filter=norm)

    script = Path(opts.lynis_script)
    share, etc = Path(opts.lynis_share_dir), Path(opts.lynis_etc_dir)
    if not script.is_file() or not (share / "include").is_dir():
        raise ConfigAuditError(f"Lynis не найден на сканере ({script}, {share})")
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        add(tar, script, "lynis/lynis", 0o755)
        add(tar, share / "include", "lynis/include", 0o644)
        add(tar, share / "db", "lynis/db", 0o644)
        if (etc / "default.prf").is_file():
            add(tar, etc / "default.prf", "lynis/default.prf", 0o644)
        if (etc / "plugins").is_dir():
            add(tar, etc / "plugins", "lynis/plugins", 0o644)
    return buf.getvalue()


def _subprocess_runner(cmd: list[str], stdin: bytes | None, timeout: float) -> RunResult:
    proc = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout,
                          check=False)
    return RunResult(proc.returncode, proc.stdout,
                     proc.stderr.decode("utf-8", "replace"))


# --- Разбор OpenSCAP (XCCDF 1.1 / 1.2) -----------------------------------------

_XCCDF_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.LOW,
    "info": Severity.INFO,
}

# Ссылки правил, показываемые в evidence (href-подстрока -> метка).
_REF_LABELS = (
    ("fstec", "ФСТЭК"),
    ("cisecurity.org/benchmark", "CIS Benchmark"),
    ("cisecurity.org", "CIS Controls"),
    ("NIST.SP.800-53", "NIST SP 800-53"),
    ("cyber.mil", "DISA"),
    ("pcisecuritystandards", "PCI DSS"),
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def _child(el: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in el if _local(c.tag) == name), None)


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _local(c.tag) == name]


def _safe_xml(data: bytes) -> ET.Element:
    head = data[:4096]
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data:
        raise ConfigAuditError("XML результатов содержит DOCTYPE/ENTITY — отклонено")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ConfigAuditError(f"не удалось разобрать XML OpenSCAP: {e}") from e


@dataclass(slots=True)
class _Rule:
    title: str
    severity: str | None
    description: str
    rationale: str
    fixtext: str
    idents: list[str]
    refs: dict[str, list[str]]


def _parse_rule(r: ET.Element) -> _Rule:
    refs: dict[str, list[str]] = {}
    for ref in _children(r, "reference"):
        href, val = ref.get("href") or "", _text(ref)
        for needle, label in _REF_LABELS:
            if needle in href and val:
                refs.setdefault(label, []).append(val)
                break
    return _Rule(title=_text(_child(r, "title")) or r.get("id", ""),
                 severity=r.get("severity"),
                 description=_text(_child(r, "description")),
                 rationale=_text(_child(r, "rationale")),
                 fixtext=_text(_child(r, "fixtext")),
                 idents=[_text(i) for i in _children(r, "ident") if _text(i)],
                 refs=refs)


def parse_openscap_results(data: bytes, host: str, module: str = "config_audit"
                           ) -> tuple[list[Finding], dict[str, str]]:
    """XCCDF results (Benchmark с TestResult) -> (находки по fail, рекомендации).

    В находки попадают только `fail`; `error`/`unknown` дают одну сводную
    info-находку (проверка не выполнена — это не нарушение, но и не «чисто»).
    """
    root = _safe_xml(data)
    rules = {r.get("id"): r for r in root.iter() if _local(r.tag) == "Rule"}
    results = [e for e in root.iter() if _local(e.tag) == "TestResult"]
    if not results:
        raise ConfigAuditError("в результатах OpenSCAP нет TestResult")
    tr = results[-1]
    profile_el = _child(tr, "profile")
    profile = profile_el.get("idref") if profile_el is not None else None
    benchmark_title = _text(_child(root, "title"))

    findings: list[Finding] = []
    remediations: dict[str, str] = {}
    errored: list[str] = []
    for rr in _children(tr, "rule-result"):
        rid = rr.get("idref") or ""
        result = _text(_child(rr, "result"))
        if result in ("error", "unknown"):
            errored.append(rid)
            continue
        if result != "fail":
            continue
        rule = _parse_rule(rules[rid]) if rid in rules else _Rule(rid, None, "", "", "", [], {})
        sev_name = rr.get("severity") or rule.severity or "unknown"
        evidence = [f"OpenSCAP: правило {rid} — результат fail"]
        if profile:
            evidence.append(f"профиль: {profile}")
        if benchmark_title:
            evidence.append(f"бенчмарк: {benchmark_title}")
        if rule.idents:
            evidence.append("идентификаторы: " + ", ".join(rule.idents))
        for label, vals in rule.refs.items():
            evidence.append(f"{label}: " + ", ".join(dict.fromkeys(vals)))
        if rule.rationale:
            evidence.append(f"обоснование: {rule.rationale}")
        findings.append(Finding(module=module, host=host, finding_type=FindingType.CONFIG,
                                title=f"[OpenSCAP] {rule.title}",
                                severity=_XCCDF_SEVERITY.get(sev_name, Severity.LOW),
                                vuln_id=rid, evidence="; ".join(evidence)))
        fix = rule.fixtext or rule.description
        if fix:
            remediations[rid] = fix
    if errored:
        findings.append(Finding(module=module, host=host, finding_type=FindingType.INFO,
                                title=f"OpenSCAP: {len(errored)} правил(а) не удалось проверить",
                                severity=Severity.INFO, vuln_id="INFO:openscap-check-error",
                                evidence=", ".join(errored[:50])))
    return findings, remediations


# --- Разбор Lynis (report.dat) -------------------------------------------------

_LYNIS_KIND = {"warning[]": Severity.MEDIUM, "suggestion[]": Severity.LOW}
_FIELD_MAX = 1000


def _field(v: str) -> str:
    v = v.strip()[:_FIELD_MAX]
    return "" if v in ("-", "") else v


def parse_lynis_report(text: str, host: str, module: str = "config_audit"
                       ) -> tuple[list[Finding], dict[str, str]]:
    """report.dat Lynis -> (находки по warning/suggestion, рекомендации).

    Строки `warning[]=ID|текст|детали|решение|`. Несколько записей с одним
    TEST-ID объединяются в одну находку (ключ сравнения прогонов — по ID), а
    уровень берётся наивысший.
    """
    meta: dict[str, str] = {}
    entries: dict[str, dict] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key not in _LYNIS_KIND:
            meta.setdefault(key, value.strip()[:_FIELD_MAX])
            continue
        parts = value.split("|")
        test_id = _field(parts[0]) if parts else ""
        if not test_id or test_id == "LYNIS":     # LYNIS — про версию самого Lynis
            continue
        message = _field(parts[1]) if len(parts) > 1 else ""
        details = _field(parts[2]) if len(parts) > 2 else ""
        solution = _field(parts[3]) if len(parts) > 3 else ""
        e = entries.setdefault(test_id, {"severity": Severity.LOW, "items": [],
                                         "solutions": []})
        sev = _LYNIS_KIND[key]
        if sev is Severity.MEDIUM:
            e["severity"] = sev
        item = message + (f" ({details})" if details else "")
        if item and item not in e["items"]:
            e["items"].append(item)
        if solution and solution not in e["solutions"]:
            e["solutions"].append(solution)

    findings: list[Finding] = []
    remediations: dict[str, str] = {}
    for test_id, e in entries.items():
        vid = f"LYNIS:{test_id}"
        kind = "предупреждение" if e["severity"] is Severity.MEDIUM else "рекомендация"
        title = e["items"][0] if e["items"] else test_id
        if len(e["items"]) > 1:
            title += f" (и ещё {len(e['items']) - 1})"
        evidence = [f"Lynis {meta.get('lynis_version', '')}".strip()
                    + f": тест {test_id} — {kind}"]
        evidence += e["items"]
        evidence.append(f"https://cisofy.com/lynis/controls/{test_id}/")
        findings.append(Finding(module=module, host=host, finding_type=FindingType.CONFIG,
                                title=f"[Lynis {test_id}] {title}", severity=e["severity"],
                                vuln_id=vid, evidence="; ".join(evidence)))
        remediations[vid] = "; ".join(e["solutions"] or e["items"])

    hi = meta.get("hardening_index")
    if hi and hi.isdigit():
        os_name = " ".join(p for p in (meta.get("os_name"), meta.get("os_version")) if p)
        findings.append(Finding(module=module, host=host, finding_type=FindingType.INFO,
                                title=f"Индекс защищённости Lynis: {hi}/100",
                                severity=Severity.INFO, vuln_id="INFO:lynis-hardening-index",
                                evidence="; ".join(p for p in (
                                    os_name and f"ОС: {os_name}",
                                    meta.get("hostname") and f"hostname: {meta['hostname']}")
                                    if p) or None))
    return findings, remediations


# --- Лимиты ----------------------------------------------------------------------

class _Throttle:
    """Минимальный интервал между стартами SSH-подключений (по всем потокам)."""

    def __init__(self, rate: RateProfile, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        per_sec = 1.0 / rate.max_requests_per_sec if rate.max_requests_per_sec > 0 else 0.0
        self.interval = max(rate.delay_between_attempts_sec, per_sec)
        self._sleep, self._clock = sleep, clock
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = self._clock()
            if now < self._next:
                self._sleep(self._next - now)
                now = self._next
            self._next = now + self.interval


# --- Модуль ----------------------------------------------------------------------

class ConfigAuditModule(ScanModule):
    name = "config_audit"

    def __init__(self, options: ConfigAuditOptions | None = None,
                 runner: Runner | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.options = options or ConfigAuditOptions()
        self._runner = runner or _subprocess_runner
        self._sleep = sleep
        self._lynis_bundle: bytes | None = None
        self._scap_payload: bytes | None = None
        self._lock = threading.Lock()
        # id правила -> рекомендация; для RemediationResolver(benchmark=...)
        self.remediations: dict[str, str] = {}

    def _credentials(self, host: str) -> SshCredentials | None:
        return self.options.host_credentials.get(host) or self.options.credentials

    def _payload(self, backend: str) -> bytes:
        with self._lock:
            if backend == OPENSCAP:
                if self._scap_payload is None:
                    path = Path(self.options.scap_content)
                    if not path.is_file():
                        raise ConfigAuditError(f"SCAP-контент не найден: {path}")
                    self._scap_payload = gzip.compress(path.read_bytes())
                return self._scap_payload
            if self._lynis_bundle is None:
                self._lynis_bundle = build_lynis_bundle(self.options)
            return self._lynis_bundle

    def _run_backend(self, ctx: ScanContext, throttle: _Throttle, host: str,
                     creds: SshCredentials, backend: str) -> list[Finding]:
        opts = self.options
        script = (openscap_script(opts.scap_profile, creds) if backend == OPENSCAP
                  else lynis_script(creds))
        cmd = build_ssh_command(host, creds, script, opts)
        details = {"backend": backend, **creds.describe(),
                   "command": redact_command(cmd, creds)}
        if backend == OPENSCAP:
            details["profile"] = opts.scap_profile
            details["content"] = Path(opts.scap_content).name
        throttle.wait()
        ctx.audit.record(subject="scanner", action="config_audit_ssh", target=host,
                         result="started", details=details)
        try:
            res = self._runner(cmd, self._payload(backend), opts.command_timeout_sec)
            if res.returncode != 0:
                raise ConfigAuditError(f"{backend}: rc={res.returncode}: "
                                       f"{res.stderr.strip()[-500:]}")
            if len(res.stdout) > MAX_OUTPUT_BYTES:
                raise ConfigAuditError(f"{backend}: вывод больше {MAX_OUTPUT_BYTES} байт")
            if backend == OPENSCAP:
                try:
                    xml = gzip.decompress(res.stdout)
                except (OSError, EOFError) as e:
                    raise ConfigAuditError(f"openscap: повреждённый вывод: {e}") from e
                if len(xml) > MAX_OUTPUT_BYTES * 4:
                    raise ConfigAuditError("openscap: результаты слишком велики")
                findings, rem = parse_openscap_results(xml, host, self.name)
            else:
                findings, rem = parse_lynis_report(
                    res.stdout.decode("utf-8", "replace"), host, self.name)
        except (ConfigAuditError, subprocess.TimeoutExpired, OSError, ValueError) as e:
            ctx.audit.record(subject="scanner", action="config_audit_ssh", target=host,
                             result="error", details={"backend": backend,
                                                      "error": str(e)[:500]})
            return [Finding(module=self.name, host=host, finding_type=FindingType.INFO,
                            title=f"Аудит конфигурации не выполнен ({backend})",
                            severity=Severity.INFO,
                            vuln_id=f"INFO:config-audit-error/{backend}",
                            evidence=str(e)[:500])]
        with self._lock:
            self.remediations.update(rem)
        ctx.audit.record(subject="scanner", action="config_audit_ssh", target=host,
                         result="ok", details={
                             "backend": backend,
                             "config_findings": sum(f.finding_type is FindingType.CONFIG
                                                    for f in findings)})
        return findings

    def _audit_host(self, ctx: ScanContext, throttle: _Throttle, host: str,
                    creds: SshCredentials) -> list[Finding]:
        findings: list[Finding] = []
        for backend in self.options.backends:
            findings += self._run_backend(ctx, throttle, host, creds, backend)
        return findings

    def run(self, ctx: ScanContext) -> list[Finding]:
        unknown = [b for b in self.options.backends if b not in BACKENDS]
        if unknown:
            raise ValueError(f"неизвестные бэкенды аудита конфигураций: {unknown}")
        targets, rejected = validate_targets(ctx.targets)
        for t in rejected:
            ctx.audit.record(subject="scanner", action="config_audit_deny", target=t,
                             result="not_an_ip_literal")
        jobs: list[tuple[str, SshCredentials]] = []
        for host in targets:
            creds = self._credentials(host)
            if creds is None:
                ctx.audit.record(subject="scanner", action="config_audit_skip",
                                 target=host, result="no_credentials")
                continue
            jobs.append((host, creds))
        if not jobs:
            return []

        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="config-audit") as pool:
            per_host = list(pool.map(lambda j: self._audit_host(ctx, throttle, *j), jobs))
        return [f for fs in per_host for f in fs]
