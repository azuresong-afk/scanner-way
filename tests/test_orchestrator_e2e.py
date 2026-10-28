"""Сквозной тест конвейера: прогон -> модуль vuln -> сопоставление с БДУ ФСТЭК
-> сохранение в БД. Проверяет, что ключевая функция (привязка находок к БДУ)
реально работает в живом прогоне через RunService, а не только в юнит-тестах
сопоставления. Без сети и без nuclei — раннер и discovery подменены.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.core import repository as repo
from scanner.core.audit import DbAuditSink
from scanner.core.db import session_scope
from scanner.core.models import Finding, FindingType, ServiceInfo
from scanner.core.orchestrator import (
    RunService,
    default_module_registry,
    inline_executor,
)
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.matcher import VulnMatcher
from scanner.feeds.store import SqlReferenceStore
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.vuln import VulnModule

SAMPLE = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()


class _StubDiscovery(ScanModule):
    """Отдаёт сервис на allowlist-хосте, чтобы было что отдавать дальше."""
    name = "discovery"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = [ServiceInfo("10.0.0.5", 8080, "tcp", "http")]
        return [Finding(module="discovery", host="10.0.0.5",
                        finding_type=FindingType.INFO, title="host up", port=8080)]


def _nuclei_runner(output: str):
    def run(cmd, stdin_targets, timeout):
        return output
    return run


@pytest.fixture
def store(sqlite_factory):
    engine = sqlite_factory.kw["bind"]
    st = SqlReferenceStore(engine)
    st.create_schema()
    # БДУ, связанная с CVE из образца nuclei (log4j, CVE-2021-44228)
    st.upsert_bdu([BduRecord(
        bdu_id="BDU:2021-06290",
        title="Уязвимость Apache Log4j (CVE-2021-44228)",
        cve_ids=["CVE-2021-44228"],
        severity_text="Критический уровень опасности (базовая оценка CVSS 3.0 составляет 10)",
        cvss_score=10.0,
        remediation="Обновить Log4j до 2.17.1 или выше",
    )])
    return st


def test_run_enriches_findings_with_bdu(sqlite_factory, store):
    with session_scope(sqlite_factory) as s:
        eid = repo.create_engagement(s, name="E2E", contract_ref="Д-E2E")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.0.0.0/24")

    registry = {
        "discovery": lambda: _StubDiscovery(),
        "vuln": lambda: VulnModule(runner=_nuclei_runner(SAMPLE),
                                   matcher=VulnMatcher(store)),
    }
    svc = RunService(sqlite_factory, DbAuditSink(sqlite_factory),
                     registry=registry, executor=inline_executor())
    run_id = svc.submit(engagement_id=eid, modules=["discovery", "vuln"],
                        rate_profile="gentle", requested_targets=["10.0.0.5"],
                        actor="tester")

    with session_scope(sqlite_factory) as s:
        run = repo.get_scan_run(s, run_id)
        assert run.status == "done"
        findings = repo.get_findings(s, run_id)

    log4j = next(f for f in findings if f.vuln_id == "CVE-2021-44228")
    assert log4j.cve_ids == ["CVE-2021-44228"]
    # Ключевая проверка: находка получила идентификатор БДУ ФСТЭК в живом прогоне.
    assert log4j.bdu_ids == ["BDU:2021-06290"]


def test_default_registry_wires_matcher_into_vuln():
    sentinel = object()
    vuln = default_module_registry(matcher=sentinel)["vuln"]()
    assert vuln._matcher is sentinel


def test_runservice_default_builds_db_backed_matcher(sqlite_factory):
    SqlReferenceStore(sqlite_factory.kw["bind"]).create_schema()
    svc = RunService(sqlite_factory, DbAuditSink(sqlite_factory),
                     executor=inline_executor())
    vuln = svc.registry["vuln"]()
    assert isinstance(vuln._matcher, VulnMatcher)
