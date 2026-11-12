"""Прогоны на узлах-сканерах (scanner.nodes): проверка узла при постановке,
выдача задания узлу и его отметка «жив»."""
from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session, sessionmaker

from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.audit import AuditSink
from scanner.core.db import session_scope

if TYPE_CHECKING:
    from scanner.core.runner.service import _Prepared


class NodeRunsMixin:
    """Часть RunService: прогоны, которые исполняет узел-сканер."""

    sessions: sessionmaker[Session]
    audit: AuditSink
    _notify: Callable[[int], None]
    _prepare: Callable[[int, str], _Prepared | str]
    _audit_start: Callable[..., None]

    def check_node(self, node_id: int | None, *, credential_ids: list[int] | None = None,
                   cred_set_ids: list[int] | None = None) -> str | None:
        """Узел прогона существует, включён и допускает учётки. -> имя узла.
        ValueError — понятная оператору причина (422)."""
        if node_id is None:
            return None
        from scanner.core.db import ScanNode
        with session_scope(self.sessions) as s:
            node = s.get(ScanNode, node_id)
            if node is None:
                raise ValueError(f"узел-сканер {node_id} не найден")
            if not node.enabled:
                raise ValueError(f"узел-сканер «{node.name}» отключён администратором")
            if (credential_ids or cred_set_ids) and not node.allow_credentials:
                raise ValueError(f"узлу «{node.name}» запрещено передавать учётные "
                                 "записи: уберите учётки или разрешите их в «Сканерах»")
            return node.name

    # --- прогоны на узлах-сканерах (scanner.nodes) --------------------------
    def claim_for_node(self, scan_run_id: int, node: object) -> dict | None:
        """Узел забирает свой pending-прогон: захват pending -> running за узлом
        и задание (scanner.nodes.codec.encode_job). None — прогон уже не pending
        или назначен другому узлу.

        Цели проходят allowlist договора, урезанный до сетей узла: узел получает
        только адреса своего сегмента; отказы пишутся в аудит центра. Учётки
        расшифровываются и уходят в задании — только если узлу это разрешено."""
        from scanner.nodes import store as nodes
        from scanner.nodes.codec import encode_job
        from scanner.nodes.jobs import build_job
        node_id = int(node.id)
        node_name = getattr(node, "name", str(node_id))
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None or run.node_id != node_id or run.status != "pending":
                return None
        p = self._prepare(scan_run_id, nodes.node_worker_id(node_id, uuid.uuid4().hex[:12]))
        if isinstance(p, str):
            return None
        if (p.credentials or p.cred_candidates) and not getattr(node, "allow_credentials",
                                                                 False):
            # админ запретил учётки узлу после постановки прогона
            p.credentials, p.cred_candidates = [], []
            msg = (f"Узлу «{node_name}» запрещено передавать учётные записи — "
                   "прогон с учётками ему не выдан.")
            with session_scope(self.sessions) as s:
                repo.set_scan_run_status(s, scan_run_id, "failed", error_message=msg)
            self.audit.record(subject="scanner", action="node_job",
                              target=f"scan_run:{scan_run_id}",
                              result="credentials_forbidden",
                              details={"node_id": node_id, "node": node_name})
            ev.safe_add(self.sessions, scan_run_id, [ev.run_finish("failed", message=msg)])
            self._notify(scan_run_id)
            return None
        job, plan = build_job(scan_run_id, p, node)
        p.credentials, p.cred_candidates = [], []
        for d in plan.denied:
            self.audit.record(subject="scanner", action="deny", target=d.target,
                              result=d.reason,
                              details={"scan_run_id": scan_run_id, "count": d.count,
                                       "node_id": node_id})
        self._audit_start(scan_run_id, p, node_id=node_id, node=node_name,
                          targets=len(job.targets))
        self.audit.record(subject="scanner", action="node_job",
                          target=f"scan_run:{scan_run_id}", result="issued",
                          details={"node_id": node_id, "node": node_name,
                                   "targets": len(job.targets),
                                   "credentials": [c.describe() for c in job.credentials]
                                   or None})
        ev.safe_add(self.sessions, scan_run_id, [ev.Event(
            "run_node", ev.SUBJECT_RUN, f"выполняется на узле «{node_name}»")])
        return encode_job(job)

    def node_heartbeat(self, scan_run_id: int, node_id: int,
                       progress: dict | None = None) -> str | None:
        """Отметка «жив» прогона на узле (+ снимок хода). -> текущий статус
        (stopped — узлу пора остановиться); None — прогон не этого узла."""
        with session_scope(self.sessions) as s:
            run = repo.get_scan_run(s, scan_run_id)
            if run is None or run.node_id != node_id:
                return None
            if run.status == "running":
                run.heartbeat_at = datetime.now(UTC)
                if progress is not None:
                    run.progress = progress
            return run.status
