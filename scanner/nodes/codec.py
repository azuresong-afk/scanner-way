"""JSON-кодек задания и результата прогона узла.

Задание (центр -> узел) и результат (узел -> центр) — обычный JSON. Dataclass-ы
кодируются как ``{"$dc": "модуль:Класс", "f": {...}}``, перечисления, даты,
множества, кортежи и байты — своими метками. Раскодируются только dataclass-ы
из пакета ``scanner`` (белый список по префиксу модуля): произвольный класс или
код из чужого JSON не создаётся — pickle не используется намеренно.

Формат версионирован (``FORMAT``): узел и центр разных версий отказываются
работать с несовместимым форматом, а не портят данные молча.
"""
from __future__ import annotations

import base64
import dataclasses
import enum
import importlib
from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from scanner.core import coverage as cv
from scanner.core.credentials import HostCredential
from scanner.core.ratelimit import PROFILES

FORMAT = 1
JOB_KIND = "scanner-node-job"
OUTCOME_KIND = "scanner-node-outcome"
_ALLOWED_PREFIX = "scanner."
MAX_DEPTH = 64


class CodecError(ValueError):
    """Данные не в формате кодека (или из несовместимой версии)."""


# ---------- общий кодек ----------
def to_wire(obj: Any, _depth: int = 0) -> Any:
    if _depth > MAX_DEPTH:
        raise CodecError("слишком глубокая вложенность")
    d = _depth + 1
    if obj is None or isinstance(obj, (bool, int, float, str)) and not isinstance(obj, enum.Enum):
        return obj
    if isinstance(obj, enum.Enum):
        cls = type(obj)
        return {"$enum": f"{cls.__module__}:{cls.__qualname__}", "v": obj.value}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        cls = type(obj)
        return {"$dc": f"{cls.__module__}:{cls.__qualname__}",
                "f": {f.name: to_wire(getattr(obj, f.name), d)
                      for f in dataclasses.fields(obj)}}
    if isinstance(obj, datetime):
        return {"$dt": obj.isoformat()}
    if isinstance(obj, date):
        return {"$date": obj.isoformat()}
    if isinstance(obj, Decimal):
        return {"$dec": str(obj)}
    if isinstance(obj, (bytes, bytearray)):
        return {"$b64": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, (set, frozenset)):
        items = [to_wire(x, d) for x in obj]
        try:
            items.sort(key=repr)
        except TypeError:
            pass
        return {"$set": items}
    if isinstance(obj, tuple):
        return {"$tuple": [to_wire(x, d) for x in obj]}
    if isinstance(obj, list):
        return [to_wire(x, d) for x in obj]
    if isinstance(obj, Mapping):
        if all(isinstance(k, str) for k in obj) and not any(k.startswith("$") for k in obj):
            return {k: to_wire(v, d) for k, v in obj.items()}
        return {"$map": [[to_wire(k, d), to_wire(v, d)] for k, v in obj.items()]}
    raise CodecError(f"тип {type(obj).__name__} не поддерживается кодеком")


def _resolve(ref: str) -> type:
    if not isinstance(ref, str) or ":" not in ref:
        raise CodecError(f"неверная ссылка на класс: {ref!r}")
    mod, _, qual = ref.partition(":")
    if not mod.startswith(_ALLOWED_PREFIX) or "." in qual or not qual.isidentifier():
        raise CodecError(f"класс вне белого списка: {ref}")
    try:
        cls = getattr(importlib.import_module(mod), qual)
    except (ImportError, AttributeError) as e:
        raise CodecError(f"класс не найден: {ref}") from e
    if not isinstance(cls, type):
        raise CodecError(f"не класс: {ref}")
    return cls


def from_wire(obj: Any, _depth: int = 0) -> Any:
    if _depth > MAX_DEPTH:
        raise CodecError("слишком глубокая вложенность")
    d = _depth + 1
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, list):
        return [from_wire(x, d) for x in obj]
    if not isinstance(obj, dict):
        raise CodecError(f"неожиданный тип {type(obj).__name__}")
    if "$dc" in obj:
        cls = _resolve(obj["$dc"])
        if not dataclasses.is_dataclass(cls):
            raise CodecError(f"не dataclass: {obj['$dc']}")
        raw = obj.get("f") or {}
        if not isinstance(raw, dict):
            raise CodecError("поля dataclass должны быть объектом")
        fields = {f.name: f for f in dataclasses.fields(cls)}
        values = {k: from_wire(v, d) for k, v in raw.items() if k in fields}
        inst = cls(**{k: v for k, v in values.items() if fields[k].init})
        for k, v in values.items():
            if not fields[k].init:
                object.__setattr__(inst, k, v)
        return inst
    if "$enum" in obj:
        cls = _resolve(obj["$enum"])
        if not issubclass(cls, enum.Enum):
            raise CodecError(f"не перечисление: {obj['$enum']}")
        return cls(obj.get("v"))
    if "$dt" in obj:
        return datetime.fromisoformat(obj["$dt"])
    if "$date" in obj:
        return date.fromisoformat(obj["$date"])
    if "$dec" in obj:
        return Decimal(obj["$dec"])
    if "$b64" in obj:
        return base64.b64decode(obj["$b64"])
    if "$set" in obj:
        return {_hashable(from_wire(x, d)) for x in obj["$set"]}
    if "$tuple" in obj:
        return tuple(from_wire(x, d) for x in obj["$tuple"])
    if "$map" in obj:
        return {_hashable(from_wire(k, d)): from_wire(v, d) for k, v in obj["$map"]}
    return {k: from_wire(v, d) for k, v in obj.items()}


def _hashable(v: Any) -> Any:
    return tuple(v) if isinstance(v, list) else v


def _check(data: Mapping, kind: str) -> None:
    if not isinstance(data, Mapping) or data.get("kind") != kind:
        raise CodecError(f"ожидался объект «{kind}»")
    if data.get("format") != FORMAT:
        raise CodecError(f"формат {data.get('format')!r} не поддерживается "
                         f"(нужен {FORMAT}): обновите узел или центральный сервер")


# ---------- задание ----------
@dataclasses.dataclass(slots=True)
class NodeJob:
    """Задание узлу: что и где проверить. Цели уже прошли allowlist договора и
    сети узла в центре; узел перепроверяет их своим локальным allowlist."""
    scan_run_id: int
    engagement_id: int
    modules: list[str]
    rate_profile: str
    targets: list[str]                     # адреса после гейта центра
    allowlist: list[str]                   # CIDR: allowlist договора ∩ сети узла
    options: dict = dataclasses.field(default_factory=dict)
    credentials: list[HostCredential] = dataclasses.field(default_factory=list)
    cred_candidates: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    progress_history: dict[str, float] = dataclasses.field(default_factory=dict)
    name: str | None = None
    node_id: int | None = None


def encode_job(job: NodeJob) -> dict:
    return {"kind": JOB_KIND, "format": FORMAT, "job": to_wire(job)}


def decode_job(data: Mapping) -> NodeJob:
    _check(data, JOB_KIND)
    job = from_wire(data.get("job"))
    if not isinstance(job, NodeJob):
        raise CodecError("в задании нет описания прогона")
    if job.rate_profile not in PROFILES:
        raise CodecError(f"неизвестный профиль скорости: {job.rate_profile}")
    if not all(isinstance(c, HostCredential) for c in job.credentials):
        raise CodecError("учётные записи задания в неверном формате")
    job.cred_candidates = [(str(a), str(b)) for a, b in job.cred_candidates]
    return job


# ---------- результат ----------
def encode_outcome(out: Any, *, scan_run_id: int) -> dict:
    """RunOutcome -> JSON. Покрытие (Coverage) — списком записей."""
    payload = {f.name: getattr(out, f.name) for f in dataclasses.fields(out)
               if f.name != "coverage"}
    payload["coverage"] = out.coverage.entries()
    return {"kind": OUTCOME_KIND, "format": FORMAT, "scan_run_id": scan_run_id,
            "outcome": to_wire(payload)}


def decode_outcome(data: Mapping) -> tuple[int, Any]:
    """JSON -> (scan_run_id, RunOutcome). Проверяет типы основных полей."""
    from scanner.core.models import Finding, HostInventory, HostOs, ServiceInfo
    from scanner.core.orchestrator import DeniedTarget, RunOutcome
    _check(data, OUTCOME_KIND)
    try:
        run_id = int(data.get("scan_run_id"))
    except (TypeError, ValueError) as e:
        raise CodecError("в результате нет номера прогона") from e
    raw = from_wire(data.get("outcome"))
    if not isinstance(raw, dict):
        raise CodecError("результат прогона в неверном формате")
    expect = {"findings": Finding, "services": ServiceInfo, "hosts": HostOs,
              "inventory": HostInventory, "denied": DeniedTarget,
              "coverage": cv.CoverageEntry}
    for key, typ in expect.items():
        items = raw.get(key) or []
        if not isinstance(items, list) or not all(isinstance(x, typ) for x in items):
            raise CodecError(f"поле результата «{key}» в неверном формате")
        raw[key] = items
    entries = raw.pop("coverage")
    for e in entries:
        if e.status not in cv.STATUS_LABELS:
            raise CodecError(f"неизвестный статус покрытия: {e.status}")
    known = {f.name for f in dataclasses.fields(RunOutcome)}
    out = RunOutcome(**{k: v for k, v in raw.items() if k in known and k != "coverage"})
    out.coverage = cv.Coverage(entries)
    out.allowed = [str(a) for a in (out.allowed or [])]
    out.errors = {str(k): str(v) for k, v in (out.errors or {}).items()}
    out.stopped = bool(out.stopped)
    out.warnings = [w for w in (out.warnings or []) if isinstance(w, dict)]
    out.compliance_facts = {str(k): v for k, v in (out.compliance_facts or {}).items()
                            if isinstance(v, dict)}
    return run_id, out
