"""Модуль 2: поиск уязвимостей (бэкенды: Nuclei, опционально OpenVAS/GVM).

Берёт сервисы из discovery (ctx.services), запускает шаблонные проверки, затем
обогащает находки через слой сопоставления (CVE/NVD + БДУ ФСТЭК).
"""
from __future__ import annotations

from scanner.modules.base import ScanContext, ScanModule


class VulnModule(ScanModule):
    name = "vuln"

    def run(self, ctx: ScanContext):
        # TODO (итерация 3): запустить Nuclei по ctx.services/targets,
        # нормализовать вывод, сопоставить с reference_nvd_cve и
        # reference_bdu_entry (feeds.matcher), вернуть Finding с cve_ids/bdu_ids.
        raise NotImplementedError("vuln: Nuclei/OpenVAS backend — итерация 3")
