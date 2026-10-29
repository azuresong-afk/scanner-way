"""Модуль 2: поиск уязвимостей (бэкенд: Nuclei).

Берёт сервисы из discovery (``ctx.services``) или цели (``ctx.targets``), строит
из них список URL/host:port, запускает по ним шаблонные проверки Nuclei и
нормализует JSONL-вывод в единый контракт :class:`Finding`. Затем, если задан
слой сопоставления (``feeds.matcher.VulnMatcher``), каждая находка обогащается
CVE/БДУ ФСТЭК, CVSS и severity — это питает приоритетную функцию продукта.

Безопасность (defense in depth поверх allowlist-гейта оркестратора):
- цели берутся из ``ctx.services``/``ctx.targets`` (уже отфильтрованы allowlist-ом);
  модуль дополнительно принимает только литеральные IP-адреса и отклоняет всё
  остальное с записью отказа в аудит — так в argv Nuclei не попадёт ни hostname,
  ни подсеть, ни опция;
- Nuclei вызывается без shell, с явными лимитами из :class:`RateProfile`
  (``-rate-limit``, ``-concurrency``) и таймаутами; сетевые взаимодействия, не
  связанные со сканированием (авто-апдейт шаблонов и телеметрия), отключены;
- каждый вызов (полная команда) и его итог пишутся в ``ctx.audit``.

Nuclei в CI не требуется: раннер (``Runner``) подменяется, а парсер проверяется
на эталонном JSONL. Живой запуск использует ``_subprocess_runner``.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shlex
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.core.ratelimit import RateProfile
from scanner.modules.base import ScanContext, ScanModule

# Раннер: (argv, targets, timeout_sec) -> JSONL со stdout; targets — список целей
# построчно. Подменяется в тестах.
Runner = Callable[[list[str], str, float], str]

# severity Nuclei -> наша шкала
_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}

# Какие схемы вытягивать из сервиса. Для TLS-портов берём https.
_TLS_SERVICES = {"https", "ssl", "https-alt", "imaps", "pop3s", "smtps", "ldaps"}
_TLS_PORTS = {443, 8443, 993, 995, 465, 636, 990}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class VulnScanError(RuntimeError):
    """Nuclei завершился с ошибкой или вернул неразбираемый вывод."""


class VulnScanTimeout(VulnScanError):
    """Nuclei не уложился в таймаут; ``partial_output`` — что он успел вывести."""

    def __init__(self, timeout: float, partial_output: str):
        super().__init__(f"nuclei не уложился в {timeout:.0f} с")
        self.partial_output = partial_output


# Оценка сверху числа запросов полного набора шаблонов Nuclei на одну цель
# (host:port/URL). Время прогона ≈ цели × запросы / rate-limit, поэтому
# таймаут считается от профиля: на gentle (5 запросов/с) одна цель — это
# десятки минут, и фиксированные 30 минут обрывали даже учебный стенд.
NUCLEI_REQUESTS_PER_INPUT = 15000
MIN_NUCLEI_TIMEOUT_SEC = 1800


@dataclass(slots=True)
class VulnOptions:
    nuclei_path: str = "nuclei"
    # Набор/серьёзность шаблонов — согласуются с заказчиком на этапе engagement.
    templates: list[str] = field(default_factory=list)      # -t (пусто = дефолтные Nuclei)
    tags: list[str] = field(default_factory=list)            # -tags
    severities: list[str] = field(default_factory=list)      # -severity (пусто = все)
    exclude_tags: list[str] = field(default_factory=lambda: ["dos", "fuzz"])
    batch_size: int = 128                                    # целей на один вызов
    timeout_per_target_sec: int = 20                         # -timeout
    # Жёсткий таймаут одного вызова. None — по профилю и числу целей
    # (nuclei_timeout); явное значение — как есть.
    overall_timeout_sec: int | None = None


def validate_targets(targets: Sequence[str]) -> tuple[list[str], list[str]]:
    """Делит цели на (валидные IP, отклонённые). Подсети и имена — отклоняются."""
    ok, rejected = [], []
    for t in targets:
        try:
            ok.append(str(ipaddress.ip_address(t.strip())))
        except ValueError:
            rejected.append(t)
    return ok, rejected


def _host_literal(host: str) -> str:
    """IPv6 в URL/host:port оборачивается в скобки."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _is_tls(service: ServiceInfo) -> bool:
    svc = (service.service or "").lower()
    return svc in _TLS_SERVICES or service.port in _TLS_PORTS


def service_to_input(service: ServiceInfo) -> str | None:
    """Строит одну строку-цель Nuclei из сервиса. Только литеральные IP."""
    try:
        ipaddress.ip_address(service.host)
    except ValueError:
        return None
    if service.protocol and service.protocol.lower() == "udp":
        return None  # Nuclei работает по TCP/HTTP; UDP-сервисы пропускаем
    host = _host_literal(service.host)
    svc = (service.service or "").lower()
    if svc in {"http", "http-alt", "http-proxy"} or service.port in {80, 8080, 8000}:
        return f"http://{host}:{service.port}"
    if _is_tls(service):
        return f"https://{host}:{service.port}"
    # прочие сервисы — как host:port, пусть Nuclei сам подберёт протокол
    return f"{host}:{service.port}"


def build_inputs(ctx: ScanContext) -> tuple[list[str], list[str]]:
    """Собирает список строк-целей Nuclei и список отклонённых исходных значений.

    Приоритет — у ``ctx.services`` (точные порты из discovery). Если сервисов нет,
    берём ``ctx.targets`` как голые хосты (Nuclei сам определит порты/схемы).
    """
    inputs: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    if ctx.services:
        for s in ctx.services:
            line = service_to_input(s)
            if line is None:
                rejected.append(f"{s.host}:{s.port}/{s.protocol}")
            elif line not in seen:
                seen.add(line)
                inputs.append(line)
    else:
        ok, bad = validate_targets(ctx.targets)
        rejected.extend(bad)
        for h in ok:
            line = _host_literal(h)
            if line not in seen:
                seen.add(line)
                inputs.append(line)
    return inputs, rejected


def build_nuclei_command(rate: RateProfile, opts: VulnOptions) -> list[str]:
    """Собирает argv Nuclei без целей: их добавляет раннер файлом (``-l``)."""
    cmd = [
        opts.nuclei_path,
        "-jsonl",                  # структурированный вывод в stdout
        "-silent",                 # без баннера/прогресса в stdout
        "-no-color",
        "-disable-update-check",   # никаких сетевых вызовов помимо сканирования
        "-rate-limit", str(max(1, int(rate.max_requests_per_sec))),
        "-concurrency", str(max(1, rate.max_concurrency)),
        "-timeout", str(opts.timeout_per_target_sec),
    ]
    for t in opts.templates:
        cmd += ["-t", t]
    if opts.tags:
        cmd += ["-tags", ",".join(opts.tags)]
    if opts.exclude_tags:
        cmd += ["-exclude-tags", ",".join(opts.exclude_tags)]
    if opts.severities:
        cmd += ["-severity", ",".join(opts.severities)]
    return cmd


def nuclei_timeout(rate: RateProfile, n_inputs: int, opts: VulnOptions) -> float:
    """Таймаут вызова Nuclei на ``n_inputs`` целей при лимите скорости профиля."""
    if opts.overall_timeout_sec is not None:
        return float(opts.overall_timeout_sec)
    rps = max(1.0, rate.max_requests_per_sec)
    return max(float(MIN_NUCLEI_TIMEOUT_SEC), n_inputs * NUCLEI_REQUESTS_PER_INPUT / rps)


def _input_host(line: str) -> str:
    """Хост из строки-цели Nuclei (``http://h:p``, ``h:p``, ``[v6]:p``)."""
    return urlsplit(line if "://" in line else f"//{line}").hostname or line


def _subprocess_runner(cmd: list[str], targets: str, timeout: float) -> str:
    # Nuclei 3.x не понимает «-l -» (ищет файл с именем «-»), поэтому цели
    # передаются временным файлом. Цели в argv так и не попадают.
    with tempfile.TemporaryDirectory(prefix="nuclei-") as tmp:
        targets_file = Path(tmp) / "targets.txt"
        targets_file.write_text(targets)
        try:
            proc = subprocess.run([*cmd, "-l", str(targets_file)],
                                  stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as e:
            # run() уже убил процесс и дочитал вывод: находки до обрыва не теряем.
            out = e.stdout or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            raise VulnScanTimeout(timeout, out) from e
    # Nuclei отдаёт rc=0 даже когда ничего не найдено; ненулевой — ошибка запуска.
    if proc.returncode != 0:
        raise VulnScanError(f"nuclei rc={proc.returncode}: {proc.stderr.strip()[:500]}")
    return proc.stdout


def _collect_cves(info: dict, classification: dict) -> list[str]:
    cves: list[str] = []
    for cid in classification.get("cve-id") or []:
        if cid:
            cves.append(cid.upper())
    # некоторые шаблоны кладут CVE только в references/теги
    for ref in info.get("reference") or []:
        for m in _CVE_RE.findall(str(ref)):
            cves.append(m.upper())
    return list(dict.fromkeys(cves))


def parse_nuclei_jsonl(output: str, module: str = "vuln") -> list[Finding]:
    """Разбирает JSONL-вывод Nuclei в список нормализованных Finding.

    Пустые строки и нераспознанные записи пропускаются (устойчивость к примесям
    в stdout). Информационные (severity=info) результаты тоже сохраняются как
    находки типа INFO — отчёт/сравнение прогонов решают, что показывать.
    """
    findings: list[Finding] = []
    for raw in output.splitlines():
        raw = raw.strip()
        if not raw or raw[0] != "{":
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue

        info = rec.get("info") or {}
        classification = info.get("classification") or {}
        template_id = rec.get("template-id") or rec.get("templateID") or "nuclei"
        host = rec.get("ip") or rec.get("host") or ""
        # host может быть URL (http://1.2.3.4:80) — вытащим адрес
        host = _extract_host(host) or _extract_host(str(rec.get("host") or "")) or host

        port = _extract_port(rec)
        sev = _SEVERITY_MAP.get(str(info.get("severity") or "").lower(), Severity.INFO)
        cves = _collect_cves(info, classification)
        cvss = classification.get("cvss-score")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None

        ftype = FindingType.VULN if sev != Severity.INFO or cves else FindingType.INFO
        # vuln_id: CVE при наличии (стабилен между прогонами), иначе id шаблона
        vuln_id = cves[0] if cves else f"NUCLEI:{template_id}"

        findings.append(Finding(
            module=module,
            host=host,
            port=port,
            finding_type=ftype,
            title=info.get("name") or template_id,
            severity=sev,
            vuln_id=vuln_id,
            cve_ids=cves,
            cvss=cvss,
            evidence=_evidence(rec, info, template_id),
        ))
    return findings


def _extract_host(value: str) -> str | None:
    if not value:
        return None
    v = value
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if v.startswith("["):                       # [ipv6]:port
        return v[1:].split("]", 1)[0]
    if v.count(":") == 1:                        # host:port
        v = v.split(":", 1)[0]
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return value if value and "://" not in value and ":" not in value else v or None


def _extract_port(rec: dict) -> int | None:
    port = rec.get("port")
    if port is not None:
        try:
            return int(port)
        except (TypeError, ValueError):
            pass
    for key in ("matched-at", "host", "url"):
        v = str(rec.get(key) or "")
        if "://" in v:
            v = v.split("://", 1)[1]
        v = v.split("/", 1)[0]
        if v.startswith("["):
            v = v.split("]", 1)[1].lstrip(":")
        elif v.count(":") == 1:
            v = v.split(":", 1)[1]
        else:
            v = ""
        if v.isdigit():
            return int(v)
    return None


def _evidence(rec: dict, info: dict, template_id: str) -> str | None:
    lines = [f"template: {template_id}"]
    matched = rec.get("matched-at") or rec.get("matched")
    if matched:
        lines.append(f"matched-at: {matched}")
    extracted = rec.get("extracted-results")
    if extracted:
        lines.append("extracted: " + ", ".join(str(x) for x in extracted[:5]))
    desc = info.get("description")
    if desc:
        lines.append(f"description: {str(desc).strip()[:300]}")
    return "; ".join(lines) or None


class _Matcher:
    """Минимальный интерфейс слоя сопоставления (feeds.matcher.VulnMatcher)."""

    def enrich(self, finding: Finding, service: ServiceInfo | None = None) -> Finding: ...


class VulnModule(ScanModule):
    name = "vuln"

    def __init__(self, options: VulnOptions | None = None,
                 runner: Runner | None = None,
                 matcher: _Matcher | None = None):
        """
        :param matcher: слой сопоставления CVE/БДУ (``feeds.matcher.VulnMatcher``).
            Если задан — каждая находка обогащается CVE/БДУ ФСТЭК, CVSS и severity.
        """
        self.options = options or VulnOptions()
        self._runner = runner or _subprocess_runner
        self._matcher = matcher

    def run(self, ctx: ScanContext) -> list[Finding]:
        inputs, rejected = build_inputs(ctx)
        for r in rejected:
            ctx.audit.record(subject="scanner", action="vuln_deny", target=r,
                             result="not_an_ip_literal")
        if not inputs:
            return []

        opts = self.options
        cmd = build_nuclei_command(ctx.rate, opts)
        findings: list[Finding] = []
        step = max(1, opts.batch_size)
        for i in range(0, len(inputs), step):
            batch = inputs[i:i + step]
            targets = "\n".join(batch) + "\n"
            ctx.audit.record(subject="scanner", action="nuclei_exec",
                             target=f"{len(batch)} targets", result="started",
                             details=shlex.join(cmd))
            timeout = nuclei_timeout(ctx.rate, len(batch), opts)
            try:
                output = self._runner(cmd, targets, timeout)
                batch_findings = parse_nuclei_jsonl(output, self.name)
            except VulnScanTimeout as e:
                # Частичный результат лучше никакого: сохраняем найденное и
                # помечаем каждый хост пачки, что проверка не завершена.
                batch_findings = parse_nuclei_jsonl(e.partial_output, self.name)
                ctx.audit.record(subject="scanner", action="nuclei_exec",
                                 target=f"{len(batch)} targets", result="timeout",
                                 details=f"{e}; findings={len(batch_findings)}")
                findings.extend(self._enrich(batch_findings, ctx.services))
                for host in dict.fromkeys(_input_host(line) for line in batch):
                    findings.append(Finding(
                        module=self.name, host=host, finding_type=FindingType.INFO,
                        title="Поиск уязвимостей прерван по таймауту — результаты неполные",
                        severity=Severity.INFO, vuln_id="INFO:vuln-scan-timeout",
                        evidence=f"{e}. Повторите прогон с профилем выше или "
                                 "с меньшим числом целей."))
                continue
            except (VulnScanError, subprocess.TimeoutExpired, OSError) as e:
                ctx.audit.record(subject="scanner", action="nuclei_exec",
                                 target=f"{len(batch)} targets", result="error",
                                 details=str(e)[:500])
                raise VulnScanError(str(e)) from e
            ctx.audit.record(subject="scanner", action="nuclei_exec",
                             target=f"{len(batch)} targets", result="ok",
                             details=f"findings={len(batch_findings)}")
            findings.extend(self._enrich(batch_findings, ctx.services))
        return findings

    def _enrich(self, findings: Iterable[Finding],
                services: list[ServiceInfo] | None) -> list[Finding]:
        """Обогащает находки через matcher, сопоставляя сервис по host:port."""
        out = list(findings)
        if self._matcher is None:
            return out
        by_hostport: dict[tuple[str, int | None], ServiceInfo] = {}
        for s in services or []:
            by_hostport[(s.host, s.port)] = s
        for f in out:
            svc = by_hostport.get((f.host, f.port))
            self._matcher.enrich(f, svc)
        return out
