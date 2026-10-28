"""Загрузка выгрузки БДУ ФСТЭК России в reference_bdu_entry.

Выгрузка БДУ (bdu.fstec.ru) публикуется как XML/Excel. Ключевые поля:
  * идентификатор BDU:YYYY-NNNNN
  * наименование, описание, вендор/ПО, версии
  * уровень опасности (CVSS и собственная шкала)
  * СВЯЗАННЫЕ CVE  <- ключ для кросс-ссылки с NVD
  * меры по устранению

Точный формат текущей выгрузки нужно зафиксировать по актуальному файлу
(см. открытый вопрос в architecture.md).
"""
from __future__ import annotations


class BduFstecFeed:
    def __init__(self, feed_path: str):
        self.feed_path = feed_path

    def sync(self) -> int:
        # TODO (итерация 3): распарсить XML/Excel выгрузку БДУ в reference_bdu_entry,
        # заполнить cve_ids[] для связи с reference_nvd_cve.
        raise NotImplementedError("БДУ ФСТЭК sync — итерация 3")
