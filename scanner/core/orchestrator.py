"""Оркестратор прогона: allowlist-гейт -> модули -> находки.

Единственное место, где цели фильтруются через allowlist; модули получают уже
безопасный список. Каждый отказ и запуск пишется в аудит.
"""
from __future__ import annotations

from scanner.core.allowlist import AllowlistGate
from scanner.core.audit import AuditSink
from scanner.core.models import Finding
from scanner.core.ratelimit import RateProfile
from scanner.modules.base import ScanContext, ScanModule


class Orchestrator:
    def __init__(self, gate: AllowlistGate, audit: AuditSink):
        self.gate = gate
        self.audit = audit

    def run(self, *, engagement_id: int, scan_run_id: int, requested_targets: list[str],
            modules: list[ScanModule], rate: RateProfile) -> list[Finding]:
        allowed, denied = self.gate.filter(requested_targets)
        for d in denied:
            self.audit.record(subject="scanner", action="deny",
                              target=d, result="not_in_allowlist")
        if not allowed:
            return []

        ctx = ScanContext(engagement_id=engagement_id, scan_run_id=scan_run_id,
                          targets=allowed, rate=rate, audit=self.audit)
        findings: list[Finding] = []
        for module in modules:
            self.audit.record(subject="scanner", action="module_start",
                              target=module.name, result="ok")
            findings.extend(module.run(ctx))
        return findings
