"""Доменные модели (нормализованные структуры, общие для всех модулей)."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(enum.StrEnum):
    VULN = "vuln"
    CONFIG = "config"
    CRED = "cred"
    INFO = "info"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    NEW = "new"
    REGRESSION = "regression"


@dataclass(slots=True)
class ServiceInfo:
    host: str
    port: int
    protocol: str            # tcp/udp
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


@dataclass(slots=True)
class Finding:
    """Единая находка — ядро отчётов и сравнения прогонов."""
    module: str
    host: str
    finding_type: FindingType
    title: str
    severity: Severity = Severity.INFO
    port: int | None = None
    vuln_id: str | None = None          # CVE-… или BDU:…
    cve_ids: list[str] = field(default_factory=list)
    bdu_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    evidence: str | None = None
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def dedup_key(self) -> str:
        """Стабильный ключ для сравнения прогонов: host+port+vuln_id+module."""
        raw = f"{self.host}|{self.port}|{self.vuln_id}|{self.module}"
        return hashlib.sha256(raw.encode()).hexdigest()
