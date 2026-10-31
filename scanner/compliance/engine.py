"""Движок соответствия (R5): факты и находки прогона -> статусы мер -> процент.

Две стадии:

1. `evaluate_run` — при завершении прогона: для каждого профиля и хоста
   статус каждой меры с автопроверкой (passed / failed / na) и доказательства —
   какие проверки дали какой итог и какими находками. Это строки
   compliance_result. Меры без автопроверки — строки со статусом manual
   (host = None), по одной на прогон и профиль.
2. `summarize` — при просмотре/отчёте: выбор мер по уровню (класс ГИС, УЗ,
   категория КИИ, IG) с учётом адаптации набора, отметок «ложное
   срабатывание» и разреза по группе активов; процент соответствия, разбивка
   по хостам и группам, провалы с рекомендациями, «проверяется вручную».

Правила расчёта (одинаковы для хоста, группы и всей выборки):
  * проверка на хосте: failed — нарушение хотя бы в одном источнике; passed —
    хотя бы один источник реально выполнялся и нарушений нет; na — ни один
    источник на хосте не выполнялся (нет учётки, не тот тип ОС, модуль не
    запускался) — «не проверено», а не «выполнено»;
  * мера на хосте: failed — провалена хотя бы одна её проверка; passed — хотя
    бы одна проверка passed и ни одной failed; na — иначе;
  * мера по выборке хостов: failed — провалена хотя бы на одном хосте; passed
    — выполнена хотя бы на одном и нигде не провалена; na — нигде не проверена;
  * процент = passed / (passed + failed). Меры manual и na в процент не входят:
    они не занижают и не завышают результат и показываются отдельно.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from scanner.compliance.catalog import Catalog, Check, Control, Profile, WinCondition
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity

PASSED, FAILED, MANUAL, NA = "passed", "failed", "manual", "na"
STATUSES = (PASSED, FAILED, MANUAL, NA)
STATUS_LABELS = {PASSED: "Выполнена", FAILED: "Не выполнена",
                 MANUAL: "Проверяется вручную", NA: "Не проверена"}

_SSG_PREFIX = "xccdf_org.ssgproject.content_rule_"
_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3,
             Severity.CRITICAL: 4}
# Модуль находок -> факт «хост проверен этим модулем».
_VULN_COVERAGE = {"vuln": "network_vuln", "auth_inventory": "linux_inventory",
                  "win_inventory": "windows"}
_MAX_ITEMS = 20          # нарушений в доказательствах одной проверки


def _host(h: object) -> str:
    text = str(h).split("/")[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


# ---------- стадия 1: оценка прогона ----------

@dataclass(slots=True)
class _HostData:
    facts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)


@dataclass(slots=True)
class ResultRow:
    """Строка compliance_result."""
    profile: str
    host: str | None
    control: str
    status: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict:
        return {"profile": self.profile, "host": self.host, "control": self.control,
                "status": self.status, "evidence": self.evidence}


def _finding_item(f: Finding) -> dict:
    return {"kind": "finding", "key": f.dedup_key(), "vuln_id": f.vuln_id,
            "title": f.title[:300], "severity": str(f.severity)}


def _rule_matches(rule_id: str, names: tuple[str, ...]) -> str | None:
    short = rule_id.removeprefix(_SSG_PREFIX)
    return short if short in names else None


def _src_openscap(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    osc = d.facts.get("openscap") or {}
    rules: dict[str, str] = osc.get("rules") or {}
    evaluated = {r: res for r, res in rules.items()
                 if res in ("pass", "fail") and _rule_matches(r, check.openscap)}
    if not evaluated:
        return False, [], None
    failed: list[dict] = []
    by_rule = {f.vuln_id: f for f in d.findings
               if f.module == "config_audit" and f.finding_type is FindingType.CONFIG}
    for rid, res in sorted(evaluated.items()):
        if res != "fail":
            continue
        f = by_rule.get(rid)
        failed.append(_finding_item(f) if f is not None else
                      {"kind": "fact", "title": f"OpenSCAP: правило {rid} — fail"})
    passed = sum(res == "pass" for res in evaluated.values())
    return True, failed, f"OpenSCAP: правил {len(evaluated)}, pass {passed}"


def _src_lynis(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    executed = set((d.facts.get("lynis") or {}).get("executed") or ())
    run = [t for t in check.lynis if t in executed]
    if not run:
        return False, [], None
    ids = {f"LYNIS:{t}" for t in run}
    failed = [_finding_item(f) for f in d.findings
              if f.module == "config_audit" and f.vuln_id in ids]
    return True, failed, f"Lynis: тесты {', '.join(run)}"


def _src_password_policy(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    if not d.facts.get("password_policy"):
        return False, [], None
    ids = {f"POLICY:password-{k}" for k in check.password_policy}
    failed = [_finding_item(f) for f in d.findings
              if f.module == "password_policy" and f.vuln_id in ids]
    return True, failed, "парольная политика по конфигурации хоста"


def _win_value(policy: Mapping[str, Any], cond: WinCondition) -> int | None:
    raw = policy.get(cond.key)
    if raw is None or str(raw).strip() == "":
        return cond.missing
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def _win_ok(policy: Mapping[str, Any], cond: WinCondition) -> bool | None:
    v = _win_value(policy, cond)
    if v is None:
        return None
    return {"eq": v == cond.value, "ne": v != cond.value,
            "ge": v >= cond.value, "le": v <= cond.value}[cond.op]


def _src_windows(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    policy = d.facts.get("windows_policy")
    if not policy:
        return False, [], None
    evaluated, failed, notes = False, [], []
    for cond in check.windows:
        if cond.when is not None:
            applies = _win_ok(policy, cond.when)
            if applies is None:
                continue
            if not applies:           # условие применимости не выполнено — мера не нужна
                evaluated = True
                notes.append(f"{cond.when.key}={policy.get(cond.when.key, '—')}: не требуется")
                continue
        ok = _win_ok(policy, cond)
        if ok is None:
            continue
        evaluated = True
        shown = policy.get(cond.key, f"не задано (по умолчанию {cond.missing})")
        notes.append(f"{cond.key}={shown}")
        if not ok:
            op = {"eq": "=", "ne": "≠", "ge": "≥", "le": "≤"}[cond.op]
            failed.append({"kind": "fact",
                           "title": f"Windows: {cond.key}={shown}, требуется {op} {cond.value}"})
    return evaluated, failed, ("Windows: " + ", ".join(notes)) if notes else None


def _src_vulns(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    spec = check.vulns or {}
    modules = tuple(spec.get("modules") or _VULN_COVERAGE)
    covered = [m for m in modules if d.facts.get(_VULN_COVERAGE.get(m, m))]
    if not covered:
        return False, [], None
    floor = _SEV_RANK[Severity(spec["min_severity"])]
    hits = [f for f in d.findings if f.finding_type is FindingType.VULN
            and f.module in modules and _SEV_RANK[f.severity] >= floor]
    hits.sort(key=lambda f: (-_SEV_RANK[f.severity], f.vuln_id or ""))
    return True, [_finding_item(f) for f in hits], f"уязвимости: {', '.join(covered)}"


def _src_services(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    if not d.facts.get("discovery"):
        return False, [], None
    spec = check.services or {}
    names = {n.lower() for n in spec.get("names") or ()}
    tcp, udp = set(spec.get("tcp_ports") or ()), set(spec.get("udp_ports") or ())
    failed = []
    for s in sorted(d.services, key=lambda s: (s.protocol, s.port)):
        proto = (s.protocol or "tcp").lower()
        by_port = s.port in (tcp if proto == "tcp" else udp)
        svc = (s.service or "").lower()
        if by_port or svc in names:
            failed.append({"kind": "fact",
                           "title": f"открыт {s.port}/{proto} ({s.service or 'сервис'})"})
    return True, failed, "сервисы по данным discovery"


def _src_cred(check: Check, d: _HostData) -> tuple[bool, list[dict], str | None]:
    creds = [f for f in d.findings if f.finding_type is FindingType.CRED]
    if not d.facts.get("cred_audit") and not creds:
        return False, [], None
    return True, [_finding_item(f) for f in creds], "проверка учётных данных по наборам оператора"


_SOURCES = (
    ("openscap", _src_openscap), ("lynis", _src_lynis),
    ("password_policy", _src_password_policy), ("windows", _src_windows),
    ("vulns", _src_vulns), ("services", _src_services), ("cred_audit", _src_cred),
)


def evaluate_check(check: Check, d: _HostData) -> dict:
    """Итог одной проверки на хосте: {id, status, sources, failures}."""
    evaluated, failures, sources = False, [], []
    for attr, fn in _SOURCES:
        if not getattr(check, attr):
            continue
        ok, failed, note = fn(check, d)
        if ok:
            evaluated = True
            failures.extend(failed)
            if note:
                sources.append(note)
    status = (FAILED if failures else PASSED) if evaluated else NA
    return {"id": check.id, "status": status, "sources": sources,
            "failures": failures[:_MAX_ITEMS], "more": max(0, len(failures) - _MAX_ITEMS)}


def _control_status(checks: Iterable[dict]) -> str:
    st = {c["status"] for c in checks}
    return FAILED if FAILED in st else PASSED if PASSED in st else NA


def _group_hosts(facts: Mapping[str, Mapping[str, Any]], findings: Iterable[Finding],
                 services: Iterable[ServiceInfo]) -> dict[str, _HostData]:
    data: dict[str, _HostData] = {}
    for h, f in facts.items():
        data.setdefault(_host(h), _HostData()).facts = dict(f)
    for f in findings:
        data.setdefault(_host(f.host), _HostData()).findings.append(f)
    for s in services:
        data.setdefault(_host(s.host), _HostData()).services.append(s)
    return data


def _evaluate_static(profile: Profile, catalog: Catalog,
                     hosts: Mapping[str, _HostData]) -> list[ResultRow]:
    rows = [ResultRow(profile.id, None, c.id, MANUAL, {})
            for c in profile.controls if c.manual]
    for host in sorted(hosts):
        d = hosts[host]
        cache: dict[str, dict] = {}
        host_rows = []
        for c in profile.controls:
            if c.manual:
                continue
            results = []
            for cid in c.checks:
                if cid not in cache:
                    cache[cid] = evaluate_check(catalog.checks[cid], d)
                results.append(cache[cid])
            host_rows.append(ResultRow(profile.id, host, c.id, _control_status(results),
                                       {"checks": results}))
        if any(r.status != NA for r in host_rows):
            rows.extend(host_rows)
    return rows


def _evaluate_cis(profile: Profile, hosts: Mapping[str, _HostData]) -> list[ResultRow]:
    """Динамический профиль CIS Benchmark: пункты из ссылок правил OpenSCAP."""
    rows: list[ResultRow] = []
    for host in sorted(hosts):
        d = hosts[host]
        osc = d.facts.get("openscap") or {}
        if "cis" not in str(osc.get("profile") or "").lower():
            continue
        rules: dict[str, str] = osc.get("rules") or {}
        by_rule = {f.vuln_id: f for f in d.findings
                   if f.module == "config_audit" and f.finding_type is FindingType.CONFIG}
        items: dict[str, dict] = {}
        for rid, meta in (osc.get("cis") or {}).items():
            res = rules.get(rid)
            if res not in ("pass", "fail"):
                continue
            for ref in meta.get("refs") or ():
                it = items.setdefault(ref, {"title": meta.get("title") or rid, "rules": [],
                                            "failures": []})
                it["rules"].append({"rule": rid.removeprefix(_SSG_PREFIX), "result": res})
                if res == "fail":
                    f = by_rule.get(rid)
                    it["failures"].append(_finding_item(f) if f is not None else
                                          {"kind": "fact", "title": f"правило {rid} — fail"})
        for ref, it in items.items():
            status = FAILED if it["failures"] else PASSED
            rows.append(ResultRow(profile.id, host, ref, status, {
                "title": it["title"],
                "checks": [{"id": "openscap", "status": status,
                            "sources": [f"OpenSCAP: {r['rule']} — {r['result']}"
                                        for r in it["rules"]][:_MAX_ITEMS],
                            "failures": it["failures"][:_MAX_ITEMS], "more": 0}]}))
    return rows


def evaluate_run(catalog: Catalog, facts: Mapping[str, Mapping[str, Any]],
                 findings: Iterable[Finding], services: Iterable[ServiceInfo] = (),
                 profiles: Collection[str] | None = None) -> list[ResultRow]:
    """Строки compliance_result по всем (или выбранным) профилям каталога."""
    findings = list(findings)
    hosts = _group_hosts(facts, findings, list(services))
    rows: list[ResultRow] = []
    for p in catalog.profiles.values():
        if profiles is not None and p.id not in profiles:
            continue
        rows.extend(_evaluate_cis(p, hosts) if p.dynamic == "openscap_cis"
                    else _evaluate_static(p, catalog, hosts))
    return rows


# ---------- стадия 2: сводка ----------

@dataclass(slots=True)
class Selection:
    """Выбор мер: уровень и адаптация базового набора (compliance_profile)."""
    level: str | None = None
    excluded: frozenset[str] = frozenset()
    added: frozenset[str] = frozenset()


def _apply_fp(check: dict, fp: Collection[str]) -> dict:
    """Нарушения, отмеченные как ложные срабатывания, не считаются."""
    if check["status"] != FAILED or not fp:
        return check
    left = [x for x in check.get("failures") or () if x.get("key") not in fp]
    if len(left) == len(check.get("failures") or ()):
        return check
    return {**check, "failures": left, "status": FAILED if left or check.get("more") else PASSED,
            "false_positives": len(check["failures"]) - len(left)}


def _percent(passed: int, failed: int) -> float | None:
    return round(100.0 * passed / (passed + failed), 1) if passed + failed else None


def _counts(statuses: Iterable[str]) -> dict[str, int]:
    out = dict.fromkeys(STATUSES, 0)
    for s in statuses:
        out[s] += 1
    return out


def _roll(statuses: Collection[str]) -> str:
    return FAILED if FAILED in statuses else PASSED if PASSED in statuses else NA


def selected_controls(profile: Profile, sel: Selection) -> list[Control]:
    base = {c.id for c in profile.base_set(sel.level)}
    ids = (base - set(sel.excluded)) | {c for c in sel.added if profile.control(c)}
    return [c for c in profile.controls if c.id in ids]


def summarize(profile: Profile, catalog: Catalog, rows: Iterable[ResultRow], *,
              selection: Selection | None = None,
              false_positives: Collection[str] = (),
              hosts: Collection[str] | None = None,
              groups: Mapping[str, Collection[str]] | None = None) -> dict:
    """Сводка соответствия профилю. hosts — ограничить выборку (разрез по группе);
    groups — {имя группы: адреса} для разбивки по группам активов."""
    sel = selection or Selection(level=profile.default_level)
    fp = set(false_positives)
    allowed = {_host(h) for h in hosts} if hosts is not None else None
    host_rows: dict[str, dict[str, dict]] = {}       # control -> host -> evidence
    host_status: dict[str, dict[str, str]] = {}      # control -> host -> status
    titles: dict[str, str] = {}
    for r in rows:
        if r.profile != profile.id or r.host is None:
            continue
        h = _host(r.host)
        if allowed is not None and h not in allowed:
            continue
        checks = [_apply_fp(c, fp) for c in r.evidence.get("checks") or ()]
        status = _control_status(checks) if checks else r.status
        host_rows.setdefault(r.control, {})[h] = {"checks": checks}
        host_status.setdefault(r.control, {})[h] = status
        if r.evidence.get("title"):
            titles[r.control] = r.evidence["title"]

    if profile.dynamic:
        controls = [Control(id=cid, title=titles.get(cid, cid), group=cid.split(".")[0],
                            group_title=f"Раздел {cid.split('.')[0]}", levels=(),
                            checks=("openscap",))
                    for cid in sorted(host_status, key=_natural)]
    else:
        controls = selected_controls(profile, sel)

    all_hosts = sorted({h for st in host_status.values() for h in st}, key=_natural_ip)
    items, manual = [], []
    for c in controls:
        if c.manual:
            manual.append({"id": c.id, "title": c.title, "group": c.group,
                           "group_title": c.group_title})
            continue
        per_host = host_status.get(c.id, {})
        status = _roll(set(per_host.values()))
        item = {"id": c.id, "title": c.title, "group": c.group, "group_title": c.group_title,
                "status": status, "hosts": _counts(per_host.values()),
                "added": c.id in sel.added}
        if status == FAILED:
            item["failed_hosts"] = []
            for h, st in sorted(per_host.items(), key=lambda kv: _natural_ip(kv[0])):
                if st != FAILED:
                    continue
                checks = [x for x in host_rows[c.id][h]["checks"] if x["status"] == FAILED]
                item["failed_hosts"].append({"host": h, "checks": [
                    {"id": x["id"], "failures": x.get("failures") or [], "more": x.get("more", 0)}
                    for x in checks]})
            failed_checks = sorted({x["id"] for fh in item["failed_hosts"] for x in fh["checks"]})
            item["recommendations"] = [_rec(catalog, cid) for cid in failed_checks]
        items.append(item)

    counts = _counts(i["status"] for i in items)
    counts[MANUAL] = len(manual)
    per_host = []
    for h in all_hosts:
        st = [host_status.get(i["id"], {}).get(h, NA) for i in items]
        k = _counts(st)
        per_host.append({"host": h, "passed": k[PASSED], "failed": k[FAILED], "na": k[NA],
                         "percent": _percent(k[PASSED], k[FAILED])})
    per_group = []
    for name, members in (groups or {}).items():
        gm = {_host(m) for m in members} & set(all_hosts)
        if not gm:
            continue
        st = [_roll({host_status.get(i["id"], {}).get(h, NA) for h in gm}) for i in items]
        k = _counts(st)
        per_group.append({"group": name, "hosts": len(gm), "passed": k[PASSED],
                          "failed": k[FAILED], "na": k[NA],
                          "percent": _percent(k[PASSED], k[FAILED])})
    return {
        "profile": {"id": profile.id, "title": profile.title, "short": profile.short,
                    "document": profile.document, "url": profile.url,
                    "level_label": profile.level_label, "levels": list(profile.levels)},
        "level": sel.level if profile.levels else None,
        "adapted": {"excluded": sorted(sel.excluded), "added": sorted(sel.added)},
        "percent": _percent(counts[PASSED], counts[FAILED]),
        "counts": counts,
        "evaluated": counts[PASSED] + counts[FAILED],
        "automated": len(items),
        "hosts": per_host,
        "groups": per_group,
        "controls": items,
        "failures": [i for i in items if i["status"] == FAILED],
        "manual": manual,
    }


def _rec(catalog: Catalog, check_id: str) -> dict:
    c = catalog.checks.get(check_id)
    if c is None:        # динамический CIS: рекомендация — в находке правила
        return {"check": check_id, "title": "Правило бенчмарка CIS",
                "remediation": "См. рекомендацию правила в находке аудита конфигурации.",
                "doc": None}
    return {"check": c.id, "title": c.title, "remediation": c.remediation, "doc": c.doc}


def _natural(s: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in s.split("."))


def _natural_ip(s: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(s)))
    except ValueError:
        return (1, s)
