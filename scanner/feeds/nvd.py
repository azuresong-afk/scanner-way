"""Загрузка справочника NVD (CVE) в reference_nvd_cve."""
from __future__ import annotations


class NvdFeed:
    def sync(self) -> int:
        # TODO (итерация 2): загрузить NVD JSON/API 2.0 (CVE, CVSS, CPE, refs),
        # upsert в reference_nvd_cve. Вернуть число обновлённых записей.
        raise NotImplementedError("NVD sync — итерация 2")
