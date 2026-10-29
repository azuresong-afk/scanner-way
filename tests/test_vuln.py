"""Тесты модуля vuln на эталонном JSONL Nuclei — без реального сканирования."""
import json
import os
import subprocess
from pathlib import Path

from scanner.core.models import FindingType, ServiceInfo, Severity
from scanner.core.ratelimit import get_profile
from scanner.modules.base import ScanContext
from scanner.modules.vuln import (
    VulnModule,
    VulnOptions,
    VulnScanError,
    VulnScanTimeout,
    build_inputs,
    build_nuclei_command,
    nuclei_timeout,
    parse_nuclei_jsonl,
    service_to_input,
    validate_targets,
)

SAMPLE = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()


class ListAudit:
    def __init__(self):
        self.records = []

    def record(self, **kw):
        self.records.append(kw)


def _ctx(targets=None, services=None, profile="gentle"):
    return ScanContext(engagement_id=1, scan_run_id=1, targets=targets or [],
                       rate=get_profile(profile), audit=ListAudit(), services=services)


def _runner(output):
    calls = []

    def run(cmd, stdin, timeout):
        calls.append({"cmd": cmd, "stdin": stdin, "timeout": timeout})
        return output

    run.calls = calls
    return run


# ---------- парсинг ----------

def test_parse_normalizes_findings():
    findings = parse_nuclei_jsonl(SAMPLE)
    # 5 валидных записей; строки-шум и пустые — пропущены
    assert len(findings) == 5
    log4j = findings[0]
    assert log4j.vuln_id == "CVE-2021-44228"
    assert log4j.cve_ids == ["CVE-2021-44228"]
    assert log4j.severity == Severity.CRITICAL
    assert log4j.finding_type == FindingType.VULN
    assert log4j.host == "10.0.0.5" and log4j.port == 8080
    assert log4j.cvss == 10.0


def test_info_result_without_cve_is_info_type():
    f = next(f for f in parse_nuclei_jsonl(SAMPLE) if f.title == "Wappalyzer Technology Detection")
    assert f.finding_type == FindingType.INFO
    assert f.severity == Severity.INFO
    assert f.vuln_id == "NUCLEI:tech-detect"   # нет CVE -> id шаблона


def test_cvss_parsed_from_string_and_cve_from_reference():
    hb = next(f for f in parse_nuclei_jsonl(SAMPLE) if f.title == "OpenSSL Heartbleed")
    assert hb.cvss == 7.5                       # строка "7.5" -> float
    assert hb.cve_ids == ["CVE-2014-0160"]      # вытащен из reference
    assert hb.vuln_id == "CVE-2014-0160"
    assert hb.host == "10.0.0.6" and hb.port == 443


def test_port_extracted_from_url_when_field_missing():
    wc = next(f for f in parse_nuclei_jsonl(SAMPLE) if f.title == "Weak TLS Cipher")
    assert wc.host == "10.0.0.6" and wc.port == 443


def test_dedup_key_stable_across_runs():
    a = parse_nuclei_jsonl(SAMPLE)[0]
    b = parse_nuclei_jsonl(SAMPLE)[0]
    assert a.dedup_key() == b.dedup_key()


def test_garbage_output_yields_nothing():
    assert parse_nuclei_jsonl("not json\n\n[]\n{broken") == []


# ---------- построение целей ----------

def test_service_to_input_schemes():
    http = ServiceInfo(host="10.0.0.5", port=80, protocol="tcp", service="http")
    https = ServiceInfo(host="10.0.0.5", port=443, protocol="tcp", service="https")
    ssh = ServiceInfo(host="10.0.0.5", port=22, protocol="tcp", service="ssh")
    assert service_to_input(http) == "http://10.0.0.5:80"
    assert service_to_input(https) == "https://10.0.0.5:443"
    assert service_to_input(ssh) == "10.0.0.5:22"


def test_service_to_input_rejects_nonip_and_udp():
    assert service_to_input(ServiceInfo(host="evil.example.com", port=80,
                                        protocol="tcp", service="http")) is None
    assert service_to_input(ServiceInfo(host="10.0.0.5", port=53,
                                        protocol="udp", service="domain")) is None


def test_ipv6_wrapped_in_brackets():
    s = ServiceInfo(host="2001:db8::1", port=443, protocol="tcp", service="https")
    assert service_to_input(s) == "https://[2001:db8::1]:443"


def test_build_inputs_prefers_services_and_dedups():
    services = [ServiceInfo(host="10.0.0.5", port=80, protocol="tcp", service="http"),
                ServiceInfo(host="10.0.0.5", port=80, protocol="tcp", service="http"),
                ServiceInfo(host="bad.example.com", port=80, protocol="tcp", service="http")]
    inputs, rejected = build_inputs(_ctx(services=services))
    assert inputs == ["http://10.0.0.5:80"]
    assert rejected == ["bad.example.com:80/tcp"]


def test_build_inputs_falls_back_to_targets():
    inputs, rejected = build_inputs(_ctx(targets=["10.0.0.9", "nope"]))
    assert inputs == ["10.0.0.9"]
    assert rejected == ["nope"]


def test_validate_targets():
    ok, bad = validate_targets(["10.0.0.1", "10.0.0.0/24", "host"])
    assert ok == ["10.0.0.1"] and bad == ["10.0.0.0/24", "host"]


# ---------- команда ----------

def test_command_carries_rate_limits_and_disables_net():
    cmd = build_nuclei_command(get_profile("gentle"), VulnOptions())
    assert "-rate-limit" in cmd and cmd[cmd.index("-rate-limit") + 1] == "5"
    assert "-concurrency" in cmd and cmd[cmd.index("-concurrency") + 1] == "8"
    assert "-disable-update-check" in cmd
    assert "-jsonl" in cmd
    # цели не в argv и не «-l -»: их передаёт раннер файлом
    assert "-l" not in cmd and "-" not in cmd
    # dos/fuzz исключены по умолчанию
    assert cmd[cmd.index("-exclude-tags") + 1] == "dos,fuzz"


# ---------- run() + аудит ----------

def test_run_audits_and_returns_findings():
    services = [ServiceInfo(host="10.0.0.5", port=8080, protocol="tcp", service="http")]
    ctx = _ctx(services=services)
    mod = VulnModule(runner=_runner(SAMPLE))
    findings = mod.run(ctx)
    assert len(findings) == 5
    actions = [r["action"] for r in ctx.audit.records]
    assert "nuclei_exec" in actions
    assert any(r["result"] == "ok" for r in ctx.audit.records)


def test_run_denies_nonip_targets_in_audit():
    ctx = _ctx(targets=["evil.example.com"])
    mod = VulnModule(runner=_runner(""))
    assert mod.run(ctx) == []
    assert any(r["action"] == "vuln_deny" and r["result"] == "not_an_ip_literal"
               for r in ctx.audit.records)


def test_run_propagates_scan_error_and_audits_it():
    def boom(cmd, stdin, timeout):
        raise VulnScanError("nuclei rc=2: boom")

    ctx = _ctx(targets=["10.0.0.5"])
    mod = VulnModule(runner=boom)
    try:
        mod.run(ctx)
        assert False, "ожидалась VulnScanError"
    except VulnScanError:
        pass
    assert any(r["action"] == "nuclei_exec" and r["result"] == "error"
               for r in ctx.audit.records)


def test_matcher_enriches_findings():
    class FakeMatcher:
        def __init__(self):
            self.seen = []

        def enrich(self, finding, service=None):
            self.seen.append((finding.vuln_id, service))
            if finding.vuln_id == "CVE-2021-44228":
                finding.bdu_ids = ["BDU:2021-06500"]
            return finding

    services = [ServiceInfo(host="10.0.0.5", port=8080, protocol="tcp", service="http")]
    ctx = _ctx(services=services)
    matcher = FakeMatcher()
    findings = VulnModule(runner=_runner(SAMPLE), matcher=matcher).run(ctx)
    log4j = next(f for f in findings if f.vuln_id == "CVE-2021-44228")
    assert log4j.bdu_ids == ["BDU:2021-06500"]
    # сервис сопоставлен по host:port
    assert ("CVE-2021-44228", services[0]) in matcher.seen


def test_batching_splits_calls():
    services = [ServiceInfo(host=f"10.0.0.{i}", port=80, protocol="tcp", service="http")
                for i in range(1, 6)]
    runner = _runner("")
    VulnModule(options=VulnOptions(batch_size=2), runner=runner).run(_ctx(services=services))
    assert len(runner.calls) == 3   # 5 целей / batch 2 -> 3 вызова


def test_subprocess_runner_passes_targets_as_file(monkeypatch):
    """Nuclei 3.x падает на «-l -»: цели должны прийти файлом через -l <path>."""
    from scanner.modules import vuln as vuln_mod

    seen = {}

    def fake_run(argv, **kw):
        path = argv[argv.index("-l") + 1]
        seen["argv"], seen["kw"] = argv, kw
        seen["path"] = path
        with open(path) as f:
            seen["content"] = f.read()
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(vuln_mod.subprocess, "run", fake_run)
    cmd = build_nuclei_command(get_profile("gentle"), VulnOptions())
    vuln_mod._subprocess_runner(cmd, "10.0.0.5:8080\n", 10.0)
    assert seen["path"] != "-"
    assert seen["content"] == "10.0.0.5:8080\n"
    assert seen["argv"][:len(cmd)] == cmd
    assert seen["kw"]["stdin"] is subprocess.DEVNULL
    assert not os.path.exists(seen["path"])   # временный файл убран


def test_timeout_scales_with_profile_and_targets():
    opts = VulnOptions()
    gentle, normal = get_profile("gentle"), get_profile("normal")
    # одна цель на gentle — дольше прежних фиксированных 30 минут
    assert nuclei_timeout(gentle, 1, opts) > 1800
    assert nuclei_timeout(gentle, 10, opts) == 10 * nuclei_timeout(gentle, 1, opts)
    assert nuclei_timeout(normal, 1, opts) < nuclei_timeout(gentle, 1, opts)
    assert nuclei_timeout(get_profile("aggressive"), 1, opts) == 1800   # нижняя граница
    assert nuclei_timeout(gentle, 5, VulnOptions(overall_timeout_sec=60)) == 60


def test_run_keeps_partial_findings_on_timeout():
    def slow(cmd, stdin, timeout):
        raise VulnScanTimeout(timeout, SAMPLE)

    services = [ServiceInfo(host="10.0.0.5", port=8080, protocol="tcp", service="http")]
    ctx = _ctx(services=services)
    findings = VulnModule(runner=slow).run(ctx)
    assert any(f.vuln_id == "CVE-2021-44228" for f in findings)
    marker = [f for f in findings if f.vuln_id == "INFO:vuln-scan-timeout"]
    assert len(marker) == 1 and marker[0].host == "10.0.0.5"
    assert any(r["action"] == "nuclei_exec" and r["result"] == "timeout"
               for r in ctx.audit.records)


def test_subprocess_runner_turns_timeout_into_partial_result(monkeypatch):
    from scanner.modules import vuln as vuln_mod

    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"], output=SAMPLE)

    monkeypatch.setattr(vuln_mod.subprocess, "run", fake_run)
    cmd = build_nuclei_command(get_profile("gentle"), VulnOptions())
    try:
        vuln_mod._subprocess_runner(cmd, "10.0.0.5:8080\n", 10.0)
        assert False, "ожидался VulnScanTimeout"
    except VulnScanTimeout as e:
        assert e.partial_output == SAMPLE


class _BannerMatcher:
    """matcher с цепочками по версии: на Apache 2.4.49 отдаёт CVE и BDU без CVE."""

    def enrich(self, finding, service=None):
        return finding

    def findings_for_service(self, service, *, module):
        from scanner.core.models import Finding as F
        return [
            F(module=module, host=service.host, port=service.port,
              finding_type=FindingType.VULN, vuln_id="CVE-2021-41773",
              cve_ids=["CVE-2021-41773"], bdu_ids=["BDU:2021-04877"],
              title="banner CVE"),
            F(module=module, host=service.host, port=service.port,
              finding_type=FindingType.VULN, vuln_id="BDU:2099-00001",
              bdu_ids=["BDU:2099-00001"], title="banner BDU"),
        ]


def _apache():
    return [ServiceInfo(host="10.0.0.5", port=80, protocol="tcp", service="http",
                        product="Apache httpd", version="2.4.49")]


def test_banner_matching_adds_findings_when_nuclei_finds_nothing():
    ctx = _ctx(services=_apache())
    findings = VulnModule(runner=_runner(""), matcher=_BannerMatcher()).run(ctx)
    assert {f.vuln_id for f in findings} == {"CVE-2021-41773", "BDU:2099-00001"}
    assert all(f.module == "vuln" and f.port == 80 for f in findings)
    assert any(r["action"] == "banner_match" and r["result"] == "ok"
               for r in ctx.audit.records)


def test_banner_matching_skips_what_nuclei_already_found():
    nuclei_hit = json.dumps({
        "template-id": "CVE-2021-41773", "host": "http://10.0.0.5:80",
        "matched-at": "http://10.0.0.5:80/icons/.%2e/etc/passwd", "port": "80",
        "ip": "10.0.0.5",
        "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "high",
                 "classification": {"cve-id": ["cve-2021-41773"]}},
    })
    findings = VulnModule(runner=_runner(nuclei_hit + "\n"),
                          matcher=_BannerMatcher()).run(_ctx(services=_apache()))
    cve = [f for f in findings if "CVE-2021-41773" in f.cve_ids]
    assert len(cve) == 1 and cve[0].title.startswith("Apache 2.4.49")   # из Nuclei
    assert any(f.vuln_id == "BDU:2099-00001" for f in findings)


def test_banner_matching_errors_do_not_fail_module():
    class Broken(_BannerMatcher):
        def findings_for_service(self, service, *, module):
            raise RuntimeError("db down")

    ctx = _ctx(services=_apache())
    assert VulnModule(runner=_runner(""), matcher=Broken()).run(ctx) == []
    assert any(r["action"] == "banner_match" and r["result"] == "error"
               for r in ctx.audit.records)


def test_duplicate_nuclei_lines_collapse_to_one_finding():
    hit = {"template-id": "http-trace", "host": "http://10.0.0.5:80", "port": "80",
           "ip": "10.0.0.5", "info": {"name": "HTTP TRACE method enabled",
                                      "severity": "info"}}
    lines = "\n".join(json.dumps({**hit, "matched-at": u})
                      for u in ("http://10.0.0.5:80/", "http://10.0.0.5:80/x")) + "\n"
    findings = VulnModule(runner=_runner(lines)).run(_ctx(services=_apache()))
    assert [f.vuln_id for f in findings].count(findings[0].vuln_id) == 1
    assert len(findings) == 1
