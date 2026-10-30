"""ПО, к которому относится находка: продукт и версия.

Нужно для группировки уязвимостей хоста «по ПО». Отдельно не хранится —
выводится при чтении:

* находка на порту → продукт/версия сервиса на этом порту (nmap -sV);
* находка инвентаризации по учётной записи (без порта) → ПО из первой строки
  evidence («Пакет … → OpenSSH 9.2p1[, cpe…]»), которую пишет
  ``VulnMatcher.findings_for_package``.

Если ПО определить нельзя (аудит конфигурации, проверка паролей, порт без
баннера) — ``None``; интерфейс группирует такие находки по модулю.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.core.models import Finding, ServiceInfo

# «Пакет openssh-server, openssh-client (1:9.2p1-2+deb12u3) → OpenSSH 9.2p1, cpe:/a:…»
_PACKAGE_LINE = re.compile(r"^Пакет .+ → (?P<label>.+?)(?:, cpe:\S*)?$")


@dataclass(frozen=True, slots=True)
class Software:
    name: str
    version: str | None = None
    source: str = "service"     # service | package


def from_evidence(evidence: str | None) -> Software | None:
    """ПО из evidence находки по установленному пакету."""
    if not evidence:
        return None
    m = _PACKAGE_LINE.match(evidence.split("\n", 1)[0].strip())
    if not m:
        return None
    name, _, version = m.group("label").strip().rpartition(" ")
    if not name:                    # метка без версии
        return Software(name=version, source="package")
    return Software(name=name, version=version or None, source="package")


def from_service(service: ServiceInfo | None) -> Software | None:
    if service is None:
        return None
    if service.product:
        return Software(name=service.product, version=service.version or None)
    if service.service:
        return Software(name=service.service)
    return None


def software_of(finding: Finding,
                services: dict[tuple[str, int], ServiceInfo] | None = None) -> Software | None:
    """ПО находки; ``services`` — сервисы прогона по (хост, порт)."""
    if finding.port is None:
        return from_evidence(finding.evidence)
    return from_service((services or {}).get((finding.host, finding.port)))
