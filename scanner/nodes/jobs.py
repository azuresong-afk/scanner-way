"""Задание узлу в центре: цели — allowlist договора, урезанный до сетей узла.

Центр — первая линия: узел получает только адреса, которые входят и в
allowlist договора на момент выдачи, и в сети узла (scope), заданные
администратором. Вторая линия — на самом узле (scanner.nodes.agent): его
локальный allowlist (SCANNER_NODE_ALLOWLIST) пересекается с allowlist из
задания, и всё, что вне него, узел отбрасывает, даже если центр скомпрометирован.
"""
from __future__ import annotations

from typing import Any

from scanner.core.allowlist import AllowlistGate
from scanner.core.orchestrator import TargetPlan, plan_targets
from scanner.nodes.codec import NodeJob
from scanner.nodes.store import intersect_networks, scope_networks


def node_gate(contract_cidrs: list[str], node_scope: list[str]) -> tuple[AllowlistGate, list[str]]:
    """Гейт «allowlist договора ∩ сети узла» и его подсети (уходят в задание)."""
    nets = intersect_networks(contract_cidrs, scope_networks(node_scope))
    return AllowlistGate(nets), nets


def build_job(scan_run_id: int, prepared: Any, node: Any) -> tuple[NodeJob, TargetPlan]:
    contract = prepared.gate.networks
    gate, nets = node_gate(contract, list(node.scope or []))
    plan = plan_targets(gate, prepared.targets)
    job = NodeJob(scan_run_id=scan_run_id, engagement_id=prepared.engagement_id,
                  modules=list(prepared.names), rate_profile=prepared.rate.name,
                  targets=list(plan.allowed), allowlist=nets,
                  options=dict(prepared.options or {}),
                  credentials=list(prepared.credentials),
                  cred_candidates=list(prepared.cred_candidates),
                  progress_history=dict(prepared.history or {}),
                  name=prepared.name, node_id=int(node.id))
    return job, plan
