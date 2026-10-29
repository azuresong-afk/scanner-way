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


@dataclass(slots=True)
class FalsePositiveMark:
    """Отметка «ложное срабатывание» на находке хоста.

    Действует на уровне договора по dedup_key (хост+порт+vuln_id+модуль): та же
    находка в следующих прогонах тоже считается ложной, пока отметку не снимут.
    """
    dedup_key: str
    reason: str | None = None
    marked_by: str | None = None         # имя пользователя
    marked_at: datetime | None = None


@dataclass(slots=True)
class HostOs:
    """ОС хоста, определённая сканированием (см. scanner.core.osfamily)."""
    host: str
    name: str | None = None              # «Linux 4.15 - 5.8», PRETTY_NAME из os-release
    family: str | None = None            # astra, redos, ubuntu, debian, windows…
    accuracy: int | None = None          # точность nmap, %; 100 — прочитано на хосте
    source: str | None = None            # nmap | banner | ssh


@dataclass(slots=True)
class InstalledPackage:
    """Пакет, установленный на хосте (по данным менеджера пакетов)."""
    name: str
    version: str             # как отдаёт менеджер: с эпохой и ревизией дистрибутива
    manager: str             # dpkg | rpm | apk
    arch: str | None = None


@dataclass(slots=True)
class HostInventory:
    """Результат аутентифицированной инвентаризации одного хоста."""
    host: str
    os_id: str | None = None             # ID из /etc/os-release (debian, rhel, astra…)
    os_name: str | None = None           # PRETTY_NAME
    os_version: str | None = None        # VERSION_ID
    os_like: str | None = None           # ID_LIKE («debian», «rhel fedora»)
    kernel: str | None = None            # uname -srm
    hostname: str | None = None
    packages: list[InstalledPackage] = field(default_factory=list)
    credential_id: int | None = None     # какой учёткой собрано (без секретов)

    @property
    def os_label(self) -> str | None:
        return self.os_name or " ".join(p for p in (self.os_id, self.os_version) if p) or None

    @property
    def os_family(self) -> str | None:
        from scanner.core.osfamily import classify
        return classify(self.os_name, self.os_id, self.os_like)
