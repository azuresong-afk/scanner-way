"""Сохранение результата прогона (локального или с узла): инвентарь, находки
со статусами относительно предыдущего прогона, активы, соответствие и
итоговый статус. Результаты пишутся одной транзакцией вместе с очисткой
прежних строк этого прогона, поэтому повторное исполнение не плодит дублей."""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

from sqlalchemy.orm import Session, sessionmaker

from scanner.core import assets
from scanner.core import coverage as cv
from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.audit import AuditSink
from scanner.core.db import session_scope
from scanner.core.models import Finding
from scanner.core.runner.engine import RunOutcome
from scanner.core.runner.recovery import MSG_NO_TARGETS, MSG_NO_TARGETS_NODE
from scanner.reporting.diff import diff_runs

# Имя логгера — прежнее (до разделения модуля): настройки логирования и
# фильтры по нему продолжают работать.
log = logging.getLogger("scanner.core.orchestrator")


def seen_hosts(out: RunOutcome) -> list[str]:
    """Хосты, которые прогон действительно обнаружил: хоть один модуль на них
    отработал (покрытие completed), найден открытый порт или выполнена
    инвентаризация. Адрес, который nmap с -Pn «видит» без единого открытого
    порта, и недоступные цели активами не становятся."""
    found = {e.host for e in out.coverage.entries() if e.status == cv.COMPLETED}
    found |= {s.host for s in out.services}
    found |= {i.host for i in out.inventory}
    return sorted(found)


def error_summary(errors: Mapping[str, str]) -> str:
    """Ошибки модулей — одной строкой для пользователя."""
    parts = [f"модуль {m}: {e}" for m, e in errors.items()]
    return "Прогон завершён с ошибками — " + "; ".join(parts)


class PersistMixin:
    """Часть RunService: запись результата прогона и итоговый статус."""

    sessions: sessionmaker[Session]
    audit: AuditSink
    _notify: Callable[[int], None]

    def _save_compliance(self, scan_run_id: int, out: RunOutcome) -> None:
        """Статусы мер профилей соответствия (R5) по итогам прогона. Ошибка
        расчёта не влияет на итог прогона: она в аудите, а результаты можно
        пересчитать позже (POST /runs/{id}/compliance/recompute)."""
        if not out.compliance_facts and not out.findings:
            return
        try:
            from scanner.compliance import store as compliance_store
            from scanner.compliance.catalog import default_catalog
            from scanner.compliance.engine import evaluate_run
            rows = evaluate_run(default_catalog(), out.compliance_facts, out.findings,
                                out.services)
            with session_scope(self.sessions) as s:
                n = compliance_store.save_run(s, scan_run_id, out.compliance_facts, rows)
            self.audit.record(subject="scanner", action="compliance_eval",
                              target=f"scan_run:{scan_run_id}", result="ok",
                              details={"rows": n, "hosts": len(out.compliance_facts)})
        except Exception as e:  # соответствие вторично к находкам
            log.exception("scan_run %s: compliance evaluation failed", scan_run_id)
            self.audit.record(subject="scanner", action="compliance_eval",
                              target=f"scan_run:{scan_run_id}", result="error",
                              details={"error": f"{type(e).__name__}: {e}"[:500]})

    def persist_outcome(self, scan_run_id: int, out: RunOutcome) -> str:
        """Сохраняет результат прогона (локального или с узла) и выставляет
        итоговый статус. Прогон должен быть running (или stopped)."""
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None:
                raise LookupError(f"scan_run {scan_run_id} not found")
            engagement_id = run.engagement_id

        with session_scope(self.sessions) as s:
            # в той же транзакции — результаты прошлой попытки этого прогона
            repo.clear_scan_run_results(s, scan_run_id)
            if out.hosts:
                repo.save_hosts(s, scan_run_id=scan_run_id, hosts=out.hosts)
            if out.services:
                repo.save_services(s, scan_run_id=scan_run_id, services=out.services)
            if out.inventory:
                repo.save_inventory(s, scan_run_id=scan_run_id, inventories=out.inventory)
            repo.save_coverage(s, scan_run_id, out.coverage)
            repo.set_run_warnings(s, scan_run_id, out.warnings)
            # «Активы» независимо от прогонов: каждый обнаруженный хост остаётся
            # в реестре договора, даже без учётки для глубокой проверки
            assets.record_seen(s, engagement_id, seen_hosts(out),
                               source=assets.SOURCE_DISCOVERY,
                               hostnames={i.host: i.hostname for i in out.inventory
                                          if i.hostname})
            prev_id = repo.previous_scan_run_id(s, scan_run_id, coverage=out.coverage)
            statuses = {}
            fixed: list[Finding] = []
            if prev_id is not None:
                d = diff_runs(repo.get_findings(s, prev_id), out.findings,
                              repo.historically_fixed_keys(s, engagement_id, scan_run_id),
                              previous_coverage=repo.run_coverage(s, prev_id),
                              current_coverage=out.coverage)
                statuses = {f.dedup_key(): st for st, items in
                            (("open", d.open), ("new", d.new),
                             ("regression", d.regression)) for f in items}
                fixed = list(d.fixed)
            repo.save_findings(s, engagement_id=engagement_id, scan_run_id=scan_run_id,
                               findings=out.findings, statuses=statuses)
            fp_keys = set(repo.false_positive_marks(s, engagement_id))
            names = assets.hostnames(s, engagement_id)
        names.update({i.host: i.hostname for i in out.inventory if i.hostname})
        ev.safe_add(self.sessions, scan_run_id, ev.host_events(
            out.findings, statuses, fixed,
            [(g.host, g.module, cv.STATUS_LABELS.get(g.status, g.status))
             for g in out.coverage.gaps()],
            false_positive_keys=fp_keys, hostnames=names))
        self._save_compliance(scan_run_id, out)
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            s.refresh(run)
            message = None
            if out.stopped or run.status == "stopped":
                final = "stopped"
            elif not out.allowed:
                final = "failed"
                message = MSG_NO_TARGETS_NODE if run.node_id is not None else MSG_NO_TARGETS
            else:
                # итог по покрытию: недоступный хост, таймаут SSH, нет учётки —
                # не «успешно»; ошибки модулей входят в покрытие как error
                final, message = cv.run_verdict(out.coverage, out.allowed)
                if out.errors:
                    message = error_summary(out.errors) + (f". {message}" if message
                                                           else "")
            if run.status != final or message:
                repo.set_scan_run_status(s, scan_run_id, final, error_message=message)
        live = [f for f in out.findings
                if str(f.severity) != "info" and f.dedup_key() not in fp_keys]
        ev.safe_add(self.sessions, scan_run_id, [ev.run_finish(
            final, open_issues=len(live),
            new=sum(1 for f in live if statuses.get(f.dedup_key()) == "new"),
            fixed=sum(1 for f in fixed if f.dedup_key() not in fp_keys),
            message=message)])
        self.audit.record(subject="scanner", action="scan_finish",
                          target=f"scan_run:{scan_run_id}", result=final,
                          details={"targets": len(out.allowed),
                                   "denied": len(out.denied),
                                   "findings": len(out.findings),
                                   "coverage_gaps": len(out.coverage.gaps()),
                                   "errors": out.errors or None})
        self._notify(scan_run_id)
        return final
