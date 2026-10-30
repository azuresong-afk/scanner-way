"""Модуль 3: аудит конфигураций — БЕЗАГЕНТНЫЙ, по учётной записи договора.

Профили: CIS Benchmarks и, для гос-контекста, требования ФСТЭК/ГОСТ (любой
XCCDF/SCAP datastream, переданный оператором). Бэкенды: OpenSCAP и Lynis.

Доступ к хосту — учётные записи договора (`ctx.credentials`, как у
auth_inventory): SSH по паролю или ключу через `scanner.core.sshexec`
(paramiko, TOFU/known_hosts, лимит вывода). Учётка для хоста выбирается по
области действия (`credentials_for_host`: самая узкая первой); отказ во входе —
следующая учётка, не больше `MAX_CREDENTIALS_PER_HOST`.

Ход проверки одного хоста (на цели ничего не остаётся):
  1. предварительная команда без sudo, только чтение: /etc/os-release, есть ли
     oscap/timeout, uid учётки;
  2. повышение прав (`HostCredential.become`): `sudo -S -p ''` с паролем учётки
     в stdin канала SSH (не в argv, не в окружении, не в журнале) или `sudo -n`
     для ключа (нужен NOPASSWD). Сначала проверочный `sudo … true`: неверный
     пароль/нет прав — понятная ошибка и одна неудачная попытка sudo на хосте;
  3. по семейству и версии ОС выбирается datastream SSG и профиль (таблица
     `SSG_CONTENT`); нет контента для семейства (Astra, РЕД ОС, Альт…) или нет
     oscap на цели — только Lynis, причина пишется в находку-сводку;
  4. для каждого бэкенда: `mktemp -d` (0700) от имени учётки -> контент по SFTP
     (stdin занят паролем sudo) -> один `sudo sh -c` со сценарием, который
     удаляет каталог в `trap … EXIT` даже при ошибке; движок ограничен
     `timeout` на цели (зависший root-процесс не остаётся). Обрыв соединения —
     уборка каталога в отдельной сессии, её итог — в аудит.

Безопасность:
- цели приходят уже отфильтрованными allowlist-ом; модуль дополнительно
  принимает только литеральные IP; если отработал discovery — только хосты,
  которые он нашёл;
- секреты (пароль, ключ, парольная фраза) не попадают ни в аудит, ни в
  находки, ни в текст ошибок (`_scrub` вырезает их из вывода цели) — только
  `HostCredential.describe()`;
- подключения ограничены RateProfile: не больше `max_concurrency` хостов
  параллельно и минимальный интервал между подключениями;
- вывод цели недоверенный: лимит размера, XML без DOCTYPE/ENTITY;
- каждое действие (вход, sudo, передача, запуск, уборка) и его итог — в
  ctx.audit.

Результат — `Finding(finding_type=CONFIG)`: `vuln_id` = id правила бенчмарка
(XCCDF rule id или `LYNIS:<TEST-ID>`), так что ключ сравнения прогонов
стабилен; рекомендация правила — в `Finding.remediation` (сохраняется в БД и
попадает в отчёт), ссылки на документы — в evidence. Хост без учётки —
info-находка «нет учётной записи для хоста», а не молчаливый пропуск.
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import re
import shlex
import tarfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from scanner.core.credentials import (
    AUTH_PASSWORD,
    BECOME_NONE,
    HostCredential,
    credentials_for_host,
)
from scanner.core.models import Finding, FindingType, Severity
from scanner.core.osfamily import classify, family_label
from scanner.core.ratelimit import RateProfile
from scanner.core.sshexec import (
    AuthFailed,
    HostKeyMismatch,
    RemoteShell,
    SshError,
    SshOptions,
    Unreachable,
    connect,
)
from scanner.modules.base import ScanContext, ScanModule

MODULE = "config_audit"
OPENSCAP = "openscap"
LYNIS = "lynis"
BACKENDS = (OPENSCAP, LYNIS)
_BACKEND_LABEL = {OPENSCAP: "OpenSCAP", LYNIS: "Lynis"}

# Предел вывода с цели (сжатые результаты XCCDF полного SSG — единицы МБ).
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_DOCS = 5

_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
# Каталог, созданный `mktemp -d` на цели: только такой путь уходит в rm -rf.
_TMPDIR_RE = re.compile(r"^/tmp/scanner-cfg\.[A-Za-z0-9]{8,}$")

Connector = Callable[[str, HostCredential, SshOptions], RemoteShell]


class ConfigAuditError(RuntimeError):
    """Ошибка проверки одного хоста (подключение, движок, разбор вывода)."""


class SudoError(ConfigAuditError):
    """Повысить права не удалось (неверный пароль, нет NOPASSWD, нет в sudoers)."""


# --- Выбор SCAP-контента по ОС ----------------------------------------------------

# Семейство ОС (scanner.core.osfamily) -> {версия: datastream SCAP Security
# Guide}. Версия — VERSION_ID из os-release: для Ubuntu целиком («22.04»), для
# остальных — мажорная часть («9.4» -> «9»); «*» — любая версия. Семейства без
# своего SSG-контента (Astra Linux, РЕД ОС, Альт, РОСА…) сюда не входят: для них
# аудит выполняет только Lynis. Контент другого дистрибутива не подставляется:
# правила SSG привязаны к платформе и на чужой ОС дают notapplicable.
SSG_CONTENT: dict[str, dict[str, str]] = {
    "debian": {"11": "ssg-debian11-ds.xml", "12": "ssg-debian12-ds.xml",
               "13": "ssg-debian13-ds.xml"},
    "ubuntu": {"20.04": "ssg-ubuntu2004-ds.xml", "22.04": "ssg-ubuntu2204-ds.xml",
               "24.04": "ssg-ubuntu2404-ds.xml"},
    "rhel": {"8": "ssg-rhel8-ds.xml", "9": "ssg-rhel9-ds.xml", "10": "ssg-rhel10-ds.xml"},
    "centos": {"9": "ssg-cs9-ds.xml", "10": "ssg-cs10-ds.xml"},
    "almalinux": {"8": "ssg-almalinux8-ds.xml", "9": "ssg-almalinux9-ds.xml"},
    "oracle": {"8": "ssg-ol8-ds.xml", "9": "ssg-ol9-ds.xml"},
    "fedora": {"*": "ssg-fedora-ds.xml"},
    "suse": {"15": "ssg-sle15-ds.xml"},
}

# Профиль XCCDF: первый из списка, который есть в datastream. CIS уровня 1 для
# серверов — основной ориентир заказчика; standard — у дистрибутивов без CIS.
PROFILE_PREFERENCE: tuple[str, ...] = tuple(
    "xccdf_org.ssgproject.content_profile_" + p
    for p in ("cis_level1_server", "cis_server_l1", "cis", "standard"))

_PROFILE_ID_RE = re.compile(rb"<(?:[\w.-]+:)?Profile\b[^>]*?\bid=\"([^\"]+)\"")


def ssg_datastream(family: str | None, version: str | None) -> str | None:
    """Имя файла datastream SSG для ОС или None — контента для неё нет."""
    table = SSG_CONTENT.get(family or "")
    if not table:
        return None
    if "*" in table:
        return table["*"]
    v = (version or "").strip()
    if family != "ubuntu":
        v = v.split(".", 1)[0]
    return table.get(v)


def pick_profile(datastream: bytes, preferred: Sequence[str] = PROFILE_PREFERENCE
                 ) -> str | None:
    """Первый профиль из preferred, объявленный в datastream."""
    present = {m.decode("ascii", "replace") for m in _PROFILE_ID_RE.findall(datastream)}
    return next((p for p in preferred if p in present), None)


@dataclass(slots=True)
class HostOsInfo:
    """ОС цели по /etc/os-release (или по данным прошлых модулей прогона)."""
    family: str | None = None
    version: str | None = None
    label: str | None = None


def _os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z_]+", key):
            out[key] = value.strip().strip('"').strip("'")[:200]
    return out


# --- Сценарии на цели --------------------------------------------------------------

# Предварительная проверка: без sudo, только чтение, без подстановок.
PREFLIGHT_SCRIPT = r"""LC_ALL=C; export LC_ALL
echo '@@os-release'; cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
echo '@@tools'
for t in oscap timeout; do
  if command -v "$t" >/dev/null 2>&1; then echo "$t"; continue; fi
  for d in /usr/sbin /sbin /usr/local/bin /usr/local/sbin; do
    if [ -x "$d/$t" ]; then echo "$t"; break; fi
  done
done
echo '@@uid'; id -u
echo '@@end'
"""
PREFLIGHT_COMMAND = "sh -c " + shlex.quote(PREFLIGHT_SCRIPT)
MKTEMP_COMMAND = "sh -c " + shlex.quote("umask 077; mktemp -d /tmp/scanner-cfg.XXXXXXXX")


@dataclass(frozen=True, slots=True)
class Preflight:
    os: HostOsInfo
    tools: frozenset[str]
    uid: int | None


def parse_preflight(text: str) -> Preflight:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("@@"):
            current = sections.setdefault(line[2:].strip(), [])
        elif current is not None:
            current.append(line.rstrip("\r"))
    osr = _os_release("\n".join(sections.get("os-release", [])))
    label = osr.get("PRETTY_NAME") or osr.get("NAME") or None
    family = classify(label, osr.get("ID"), osr.get("ID_LIKE")) if osr else None
    uid_line = next((x.strip() for x in sections.get("uid", []) if x.strip()), "")
    return Preflight(os=HostOsInfo(family=family, version=osr.get("VERSION_ID") or None,
                                   label=label),
                     tools=frozenset(x.strip() for x in sections.get("tools", [])
                                     if x.strip() in ("oscap", "timeout")),
                     uid=int(uid_line) if uid_line.isdigit() else None)


@dataclass(frozen=True, slots=True)
class Become:
    """Как запускать команды с правами root на цели.

    prefix — начало команды (`sudo -S -p ''`, `sudo -n` или пусто); stdin —
    что подать в канал (пароль для sudo -S). Пароль не выводится в repr.
    """
    prefix: str
    mode: str                                        # sudo-password | sudo-nopasswd | root | none
    stdin: bytes | None = field(default=None, repr=False)

    def wrap(self, script: str) -> str:
        return f"{self.prefix}sh -c {shlex.quote(script)}"


def become_for(cred: HostCredential, uid: int | None) -> Become:
    if uid == 0:
        return Become("", "root")
    if cred.become == BECOME_NONE:
        return Become("", "none")
    if cred.auth == AUTH_PASSWORD and cred.password:
        return Become("sudo -S -p '' ", "sudo-password",
                      (cred.password + "\n").encode())
    return Become("sudo -n ", "sudo-nopasswd")


_BECOME_LABEL = {"sudo-password": "sudo (пароль учётки)",
                 "sudo-nopasswd": "sudo без пароля (NOPASSWD)",
                 "root": "вход под root", "none": "без повышения прав"}


def _engine_timeout(seconds: float) -> str:
    """Ограничение времени движка на цели: при обрыве связи не остаётся
    висящего root-процесса. Без coreutils timeout — без ограничения."""
    n = max(60, int(seconds))
    return (f'T=""; if command -v timeout >/dev/null 2>&1; then T="timeout -k 15 {n}"; fi')


def openscap_script(tmpdir: str, profile: str, timeout_sec: float) -> str:
    """Сценарий (под sudo): $d/ds.xml.gz -> oscap -> stdout = gzip(XCCDF results)."""
    if not _PROFILE_RE.match(profile):
        raise ValueError(f"недопустимый id профиля XCCDF: {profile!r}")
    if not _TMPDIR_RE.match(tmpdir):
        raise ValueError(f"недопустимый временный каталог: {tmpdir!r}")
    return f"""set -eu
exec </dev/null
umask 077
d={shlex.quote(tmpdir)}
trap 'rm -rf "$d"' EXIT
trap 'exit 129' HUP INT TERM
{_engine_timeout(timeout_sec)}
command -v oscap >/dev/null 2>&1 || {{ echo 'oscap (openscap-scanner) not found on target' >&2; exit 127; }}
gzip -dc "$d/ds.xml.gz" > "$d/ds.xml"
rc=0
$T oscap xccdf eval --profile {shlex.quote(profile)} --results "$d/results.xml" "$d/ds.xml" >/dev/null 2>"$d/err" || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then tail -c 2000 "$d/err" >&2; exit "$rc"; fi
gzip -c "$d/results.xml"
"""


def lynis_script(tmpdir: str, timeout_sec: float) -> str:
    """Сценарий (под sudo): $d/lynis.tar.gz -> lynis audit system -> stdout = report.dat."""
    if not _TMPDIR_RE.match(tmpdir):
        raise ValueError(f"недопустимый временный каталог: {tmpdir!r}")
    return f"""set -eu
exec </dev/null
umask 077
d={shlex.quote(tmpdir)}
trap 'rm -rf "$d"' EXIT
trap 'exit 129' HUP INT TERM
{_engine_timeout(timeout_sec)}
tar -xzf "$d/lynis.tar.gz" -C "$d"
cd "$d/lynis"
rc=0
$T ./lynis audit system --usecwd --quiet --no-colors --report-file "$d/report.dat" --logfile "$d/lynis.log" >/dev/null 2>"$d/err" || rc=$?
if ! test -s "$d/report.dat"; then
  tail -c 2000 "$d/err" >&2; [ "$rc" -ne 0 ] || rc=1; exit "$rc"
fi
cat "$d/report.dat"
"""


def cleanup_command(tmpdir: str) -> str:
    if not _TMPDIR_RE.match(tmpdir):
        raise ValueError(f"недопустимый временный каталог: {tmpdir!r}")
    return f"rm -rf -- {shlex.quote(tmpdir)}"


# --- Параметры -------------------------------------------------------------------

@dataclass(slots=True)
class ConfigAuditOptions:
    ssh: SshOptions = field(default_factory=SshOptions)
    backends: Sequence[str] = BACKENDS
    # Каталог datastream-ов SCAP Security Guide на сканере (пакеты ssg-*).
    scap_dir: str = "/usr/share/xml/scap/ssg/content"
    # Явный datastream (контент ФСТЭК/ГОСТ оператора) — для всех хостов вместо
    # таблицы SSG_CONTENT; профиль — scap_profile или первый из PROFILE_PREFERENCE.
    scap_content: str | None = None
    scap_profile: str | None = None
    # Lynis: готовый архив (официальный lynis-*.tar.gz с каталогом lynis/) или
    # сборка из установленного пакета Debian/Ubuntu.
    lynis_bundle: str | None = None
    lynis_script: str = "/usr/sbin/lynis"
    lynis_share_dir: str = "/usr/share/lynis"
    lynis_etc_dir: str = "/etc/lynis"
    command_timeout_sec: float = 1800.0  # на один движок на цели
    max_parallel_hosts: int = 4          # верхняя граница; реальная — min с RateProfile


class _AuditSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_CONFIG_AUDIT_", env_file=".env",
                                      extra="ignore")

    scap_dir: str = "/usr/share/xml/scap/ssg/content"
    scap_content: str = ""
    scap_profile: str = ""
    lynis_bundle: str = ""
    command_timeout_sec: float = 1800.0


def options_from_env() -> ConfigAuditOptions:
    from scanner.core.sshexec import options_from_env as ssh_from_env

    s = _AuditSettings()
    return ConfigAuditOptions(ssh=ssh_from_env(), scap_dir=s.scap_dir,
                              scap_content=s.scap_content or None,
                              scap_profile=s.scap_profile or None,
                              lynis_bundle=s.lynis_bundle or None,
                              command_timeout_sec=s.command_timeout_sec)


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


def _scrub(text: str, cred: HostCredential) -> str:
    """Текст с цели/из исключения -> без секретов учётки (на случай эха)."""
    for secret in (cred.password, cred.passphrase):
        if secret and len(secret) >= 3:
            text = text.replace(secret, "***")
    return text


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
    docs: list[str] = field(default_factory=list)     # href ссылок правила


def _parse_rule(r: ET.Element) -> _Rule:
    refs: dict[str, list[str]] = {}
    docs: list[str] = []
    for ref in _children(r, "reference"):
        href, val = ref.get("href") or "", _text(ref)
        if href.startswith(("https://", "http://")) and href not in docs:
            docs.append(href)
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
                 refs=refs, docs=docs[:_MAX_DOCS])


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
        if rule.docs:
            evidence.append("документы: " + " ".join(rule.docs))
        fix = rule.fixtext or rule.description
        findings.append(Finding(module=module, host=host, finding_type=FindingType.CONFIG,
                                title=f"[OpenSCAP] {rule.title}",
                                severity=_XCCDF_SEVERITY.get(sev_name, Severity.LOW),
                                vuln_id=rid, evidence="; ".join(evidence),
                                remediation=fix or None))
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
        fix = "; ".join(e["solutions"] or e["items"])
        findings.append(Finding(module=module, host=host, finding_type=FindingType.CONFIG,
                                title=f"[Lynis {test_id}] {title}", severity=e["severity"],
                                vuln_id=vid, evidence="; ".join(evidence),
                                remediation=fix or None))
        remediations[vid] = fix

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

@dataclass(slots=True)
class _Plan:
    """Что запускать на хосте: бэкенды, контент OpenSCAP и пояснения к выбору."""
    backends: list[str]
    content: str | None = None           # путь к datastream на сканере
    profile: str | None = None
    notes: list[str] = field(default_factory=list)


class _Session:
    """Подключение к хосту под конкретной учёткой (для одного хоста)."""

    def __init__(self, shell: RemoteShell, cred: HostCredential, become: Become,
                 pre: Preflight):
        self.shell, self.cred, self.become, self.pre = shell, cred, become, pre


class ConfigAuditModule(ScanModule):
    name = MODULE

    def __init__(self, options: ConfigAuditOptions | None = None,
                 connector: Connector | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.options = options or ConfigAuditOptions()
        self._connect = connector or connect
        self._sleep = sleep
        self._payloads: dict[str, bytes] = {}
        self._profiles: dict[str, str | None] = {}
        self._lock = threading.Lock()
        # id правила -> рекомендация (справочник benchmark для RemediationResolver);
        # те же тексты лежат в Finding.remediation.
        self.remediations: dict[str, str] = {}

    # --- контент ---
    def _scap(self, path: str) -> tuple[bytes, str | None]:
        """Сжатый datastream и выбранный профиль (с кэшем на прогон)."""
        with self._lock:
            if path not in self._payloads:
                p = Path(path)
                if not p.is_file():
                    raise ConfigAuditError(f"SCAP-контент не найден на сканере: {p}")
                raw = p.read_bytes()
                self._payloads[path] = gzip.compress(raw)
                self._profiles[path] = (self.options.scap_profile or pick_profile(raw))
            return self._payloads[path], self._profiles[path]

    def _lynis(self) -> bytes:
        with self._lock:
            if LYNIS not in self._payloads:
                self._payloads[LYNIS] = build_lynis_bundle(self.options)
            return self._payloads[LYNIS]

    def plan(self, os: HostOsInfo, tools: frozenset[str]) -> _Plan:
        """Бэкенды и контент для ОС хоста. Одна точка выбора SSG/Lynis."""
        opts = self.options
        wanted = list(opts.backends)
        plan = _Plan(backends=[])
        if OPENSCAP in wanted:
            content = opts.scap_content
            if not content:
                ds = ssg_datastream(os.family, os.version)
                if ds is None:
                    what = family_label(os.family) + (f" {os.version}" if os.version else "")
                    plan.notes.append(f"OpenSCAP: нет SCAP-контента SSG для «{what}» — "
                                      "аудит выполнен Lynis")
                else:
                    content = str(Path(opts.scap_dir) / ds)
            if content and "oscap" not in tools:
                plan.notes.append("OpenSCAP: на хосте нет oscap (пакет openscap-scanner "
                                  "/ openscap-utils) — аудит выполнен Lynis")
                content = None
            if content:
                try:
                    _, profile = self._scap(content)
                except ConfigAuditError as e:
                    plan.notes.append(f"OpenSCAP: {e} — аудит выполнен Lynis")
                else:
                    if profile is None:
                        plan.notes.append(f"OpenSCAP: в {Path(content).name} нет профиля "
                                          "CIS/standard — задайте "
                                          "SCANNER_CONFIG_AUDIT_SCAP_PROFILE")
                    else:
                        plan.backends.append(OPENSCAP)
                        plan.content, plan.profile = content, profile
        if LYNIS in wanted:
            plan.backends.append(LYNIS)
        return plan

    # --- подключение ---
    def _audit(self, ctx: ScanContext, action: str, host: str, result: str,
               details: dict) -> None:
        ctx.audit.record(subject="scanner", action=action, target=host, result=result,
                         details=details)

    def _open(self, ctx: ScanContext, throttle: _Throttle, host: str,
              creds: list[HostCredential]) -> tuple[_Session | None, list[Finding]]:
        """Вход и повышение прав: первая учётка, с которой это удалось."""
        notes: list[Finding] = []
        timeout = self.options.ssh.connect_timeout_sec + 60
        for cred in creds:
            info = cred.describe()
            throttle.wait()
            self._audit(ctx, "config_audit_ssh", host, "started", info)
            try:
                shell = self._connect(host, cred, self.options.ssh)
            except AuthFailed as e:
                self._audit(ctx, "config_audit_ssh", host, "auth_failed",
                            {**info, "error": _scrub(str(e), cred)[:300]})
                notes.append(_info(host, "INFO:config-audit-auth-failed",
                                   "Аудит конфигурации: вход по учётной записи отклонён",
                                   f"учётка «{cred.name}» ({cred.username}@{host}:"
                                   f"{cred.port}): {_scrub(str(e), cred)}"))
                continue
            except HostKeyMismatch as e:
                self._audit(ctx, "config_audit_ssh", host, "host_key_mismatch",
                            {**info, "error": str(e)[:300]})
                return None, [_info(host, "INFO:config-audit-host-key",
                                    "Аудит конфигурации: ключ SSH хоста не прошёл проверку",
                                    str(e))]
            except Unreachable as e:
                self._audit(ctx, "config_audit_ssh", host, "unreachable",
                            {**info, "error": str(e)[:300]})
                return None, [_info(host, "INFO:config-audit-unreachable",
                                    "Аудит конфигурации: хост недоступен по SSH",
                                    f"{host}:{cred.port}: {e}")]
            except (SshError, ValueError) as e:
                msg = _scrub(f"{type(e).__name__}: {e}", cred)
                self._audit(ctx, "config_audit_ssh", host, "error",
                            {**info, "error": msg[:300]})
                notes.append(_info(host, "INFO:config-audit-error",
                                   "Аудит конфигурации не выполнен", msg[:500]))
                continue
            try:
                res = shell.run(PREFLIGHT_COMMAND, timeout)
                pre = parse_preflight(res.stdout.decode("utf-8", "replace"))
                become = become_for(cred, pre.uid)
                self._check_become(shell, become, cred, timeout)
            except (SshError, SudoError) as e:
                shell.close()
                msg = _scrub(str(e), cred)
                kind = "sudo_failed" if isinstance(e, SudoError) else "error"
                self._audit(ctx, "config_audit_become", host, kind,
                            {**info, "error": msg[:300]})
                notes.append(_info(
                    host, "INFO:config-audit-sudo" if isinstance(e, SudoError)
                    else "INFO:config-audit-error",
                    "Аудит конфигурации: не удалось повысить права"
                    if isinstance(e, SudoError) else "Аудит конфигурации не выполнен",
                    f"учётка «{cred.name}» ({cred.username}): {msg}"[:700]))
                continue                       # другая учётка может иметь sudo
            self._audit(ctx, "config_audit_become", host, "ok",
                        {**info, "mode": become.mode, "os": pre.os.label,
                         "tools": sorted(pre.tools)})
            return _Session(shell, cred, become, pre), []
        return None, notes

    @staticmethod
    def _check_become(shell: RemoteShell, become: Become, cred: HostCredential,
                      timeout: float) -> None:
        """Проверочный `sudo … true`: ошибка до передачи контента и запуска движков."""
        if not become.prefix:
            return
        res = shell.run(f"{become.prefix}true", timeout, stdin=become.stdin)
        if res.returncode == 0:
            return
        err = _scrub(res.stderr.strip(), cred)[-300:]
        if become.mode == "sudo-nopasswd":
            raise SudoError("sudo требует пароль: для учётки с ключом нужен NOPASSWD в "
                            "sudoers, либо выберите учётку с паролем или повышение прав "
                            f"«нет» ({err or 'sudo -n отказал'})")
        raise SudoError("sudo отклонил пароль учётки или учётка не входит в sudoers "
                        f"({err or f'rc={res.returncode}'})")

    # --- запуск бэкенда ---
    def _run_backend(self, ctx: ScanContext, host: str, sess: _Session, plan: _Plan,
                     backend: str) -> list[Finding]:
        opts, cred, shell = self.options, sess.cred, sess.shell
        info = {"backend": backend, **cred.describe(), "mode": sess.become.mode}
        if backend == OPENSCAP:
            info |= {"profile": plan.profile, "content": Path(plan.content or "").name}
        short = 120.0
        tmpdir: str | None = None
        self._audit(ctx, "config_audit_exec", host, "started", info)
        try:
            if backend == OPENSCAP:
                payload, _ = self._scap(plan.content or "")
                fname = "ds.xml.gz"
            else:
                payload, fname = self._lynis(), "lynis.tar.gz"
            res = shell.run(MKTEMP_COMMAND, short)
            out = res.stdout.decode("utf-8", "replace").strip()
            if res.returncode != 0 or not _TMPDIR_RE.match(out):
                raise ConfigAuditError(f"mktemp на цели не удался: rc={res.returncode} "
                                       f"{res.stderr.strip()[-200:]}")
            tmpdir = out
            shell.put(f"{tmpdir}/{fname}", payload, max(short, opts.command_timeout_sec / 4))
            script = (openscap_script(tmpdir, plan.profile or "", opts.command_timeout_sec)
                      if backend == OPENSCAP
                      else lynis_script(tmpdir, opts.command_timeout_sec))
            res = shell.run(sess.become.wrap(script), opts.command_timeout_sec + 90,
                            stdin=sess.become.stdin)
            if res.returncode != 0:
                # trap сценария не сработает, если не запустился sudo — убираем сами
                self._cleanup(ctx, host, sess, tmpdir, same_session=True)
                tmpdir = None
                raise ConfigAuditError(f"{backend}: rc={res.returncode}: "
                                       f"{res.stderr.strip()[-500:]}")
            tmpdir = None                     # каталог убрал trap сценария
            if res.truncated or len(res.stdout) > MAX_OUTPUT_BYTES:
                raise ConfigAuditError(f"{backend}: вывод больше допустимого")
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
        except SshError as e:
            msg = _scrub(str(e), cred)
            self._audit(ctx, "config_audit_exec", host, "error",
                        {**info, "error": msg[:500]})
            if tmpdir:
                self._cleanup(ctx, host, sess, tmpdir, same_session=False)
            return [self._error(host, backend, msg)]
        except (ConfigAuditError, OSError, ValueError) as e:
            msg = _scrub(str(e), cred)
            self._audit(ctx, "config_audit_exec", host, "error",
                        {**info, "error": msg[:500]})
            if tmpdir:
                self._cleanup(ctx, host, sess, tmpdir, same_session=True)
            return [self._error(host, backend, msg)]

        used = (f"учётная запись: «{cred.name}» ({cred.username}, {cred.auth}, "
                f"{_BECOME_LABEL[sess.become.mode]}); бэкенд: {_BACKEND_LABEL[backend]}")
        for f in findings:
            if f.finding_type is FindingType.CONFIG:
                f.evidence = f"{f.evidence}; {used}" if f.evidence else used
        with self._lock:
            self.remediations.update(rem)
        self._audit(ctx, "config_audit_exec", host, "ok", {
            **info, "config_findings": sum(f.finding_type is FindingType.CONFIG
                                           for f in findings)})
        return findings

    def _cleanup(self, ctx: ScanContext, host: str, sess: _Session, tmpdir: str, *,
                 same_session: bool) -> None:
        """Удалить временный каталог на цели; при обрыве — в новой сессии."""
        cmd = sess.become.prefix + cleanup_command(tmpdir)
        shell, opened = sess.shell, False
        try:
            if not same_session:
                shell, opened = self._connect(host, sess.cred, self.options.ssh), True
            res = shell.run(cmd, 60.0, stdin=sess.become.stdin)
            result = "ok" if res.returncode == 0 else "error"
            detail = {"tmpdir": tmpdir, "rc": res.returncode,
                      "new_session": not same_session}
        except (SshError, ValueError) as e:
            result = "error"
            detail = {"tmpdir": tmpdir, "new_session": not same_session,
                      "error": _scrub(str(e), sess.cred)[:300]}
        finally:
            if opened:
                shell.close()
        self._audit(ctx, "config_audit_cleanup", host, result, detail)

    def _error(self, host: str, backend: str, msg: str) -> Finding:
        return Finding(module=self.name, host=host, finding_type=FindingType.INFO,
                       title=f"Аудит конфигурации не выполнен ({_BACKEND_LABEL[backend]})",
                       severity=Severity.INFO, vuln_id=f"INFO:config-audit-error/{backend}",
                       evidence=msg[:500])

    def _summary(self, host: str, sess: _Session, plan: _Plan, os: HostOsInfo,
                 findings: list[Finding]) -> Finding:
        cred = sess.cred
        lines = [f"ОС: {os.label or family_label(os.family)}"]
        done = [b for b in plan.backends
                if not any(f.vuln_id == f"INFO:config-audit-error/{b}" for f in findings)]
        if OPENSCAP in plan.backends:
            lines.append(f"OpenSCAP: {Path(plan.content or '').name}, профиль {plan.profile}")
        lines += plan.notes
        lines.append(f"учётная запись: «{cred.name}» ({cred.username}, {cred.auth})")
        lines.append(f"повышение прав: {_BECOME_LABEL[sess.become.mode]}")
        if sess.become.mode == "none":
            lines.append("без root часть правил не проверяется (нет доступа к "
                         "/etc/shadow, настройкам аудита и т. п.)")
        n = sum(f.finding_type is FindingType.CONFIG for f in findings)
        lines.append(f"нарушений конфигурации: {n}")
        label = ", ".join(_BACKEND_LABEL[b] for b in done) or "не выполнен"
        return _info(host, "INFO:config-audit",
                     f"Аудит конфигурации: {os.label or host} — {label}",
                     "\n".join(lines))

    def _host_os(self, ctx: ScanContext, host: str, pre: Preflight) -> HostOsInfo:
        """ОС из os-release цели; если прочитать не удалось — из прошлых модулей."""
        if pre.os.family:
            return pre.os
        inv = ctx.inventory.get(host)
        if inv is not None and inv.os_family:
            return HostOsInfo(inv.os_family, inv.os_version, inv.os_label)
        h = ctx.hosts.get(host)
        if h is not None and h.family:
            return HostOsInfo(h.family, None, h.name)
        return pre.os

    def _audit_host(self, ctx: ScanContext, throttle: _Throttle, host: str,
                    creds: list[HostCredential]) -> list[Finding]:
        sess, notes = self._open(ctx, throttle, host, creds)
        if sess is None:
            return notes
        try:
            os = self._host_os(ctx, host, sess.pre)
            plan = self.plan(os, sess.pre.tools)
            findings: list[Finding] = []
            for backend in plan.backends:
                findings += self._run_backend(ctx, host, sess, plan, backend)
            return [self._summary(host, sess, plan, os, findings), *findings]
        finally:
            sess.shell.close()

    def _hosts(self, ctx: ScanContext) -> list[str]:
        hosts = []
        for t in ctx.targets:
            try:
                hosts.append(str(ipaddress.ip_address(t.strip())))
            except ValueError:
                ctx.audit.record(subject="scanner", action="config_audit_deny", target=t,
                                 result="not_an_ip_literal")
        if "discovery" in ctx.completed and ctx.services is not None:
            # discovery отработал: не входим по SSH на хосты, которых он не нашёл
            alive = {s.host for s in ctx.services}
            for h in hosts:
                if h not in alive:
                    ctx.audit.record(subject="scanner", action="config_audit_skip",
                                     target=h, result="host_not_discovered")
            hosts = [h for h in hosts if h in alive]
        return hosts

    def run(self, ctx: ScanContext) -> list[Finding]:
        unknown = [b for b in self.options.backends if b not in BACKENDS]
        if unknown:
            raise ValueError(f"неизвестные бэкенды аудита конфигураций: {unknown}")
        findings: list[Finding] = []
        jobs: list[tuple[str, list[HostCredential]]] = []
        for host in self._hosts(ctx):
            creds = credentials_for_host(host, ctx.credentials)
            if not creds:
                ctx.audit.record(subject="scanner", action="config_audit_skip",
                                 target=host, result="no_credentials")
                findings.append(_info(
                    host, "INFO:config-audit-no-credentials",
                    "Аудит конфигурации: нет учётной записи для хоста",
                    "ни одна учётка, выбранная для прогона, не подходит хосту по "
                    "области действия — добавьте учётку в договор и выберите её при "
                    "запуске"))
                continue
            jobs.append((host, creds))
        if not jobs:
            return findings

        throttle = _Throttle(ctx.rate, sleep=self._sleep)
        workers = max(1, min(self.options.max_parallel_hosts, ctx.rate.max_concurrency,
                             len(jobs)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="config-audit") as pool:
            per_host = list(pool.map(lambda j: self._audit_host(ctx, throttle, *j), jobs))
        return findings + [f for fs in per_host for f in fs]


def _info(host: str, vuln_id: str, title: str, evidence: str | None) -> Finding:
    return Finding(module=MODULE, host=host, finding_type=FindingType.INFO, title=title,
                   severity=Severity.INFO, vuln_id=vuln_id, evidence=evidence)
