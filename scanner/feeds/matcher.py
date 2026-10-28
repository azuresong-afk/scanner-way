"""Слой сопоставления находок с базами уязвимостей (NVD + БДУ ФСТЭК)."""
from __future__ import annotations

from scanner.core.models import Finding


class VulnMatcher:
    def enrich(self, finding: Finding) -> Finding:
        # TODO: по CVE -> запись NVD + связанная запись БДУ;
        # по сервис+версия -> CPE -> CVE -> далее как выше.
        # Заполняет finding.cve_ids, finding.bdu_ids, finding.cvss, severity.
        raise NotImplementedError("сопоставление NVD/БДУ — итерация 3")
