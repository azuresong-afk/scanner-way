"""RHEL и совместимые (CentOS, Rocky, AlmaLinux, Oracle Linux, МСВСфера):
OVAL v2 Red Hat (security.access.redhat.com), файл на основной выпуск.

Совместимые дистрибутивы собирают пакеты из тех же исходников с теми же
версиями (``3.0.7-27.el9_3``), поэтому сверяются с данными Red Hat; в находке
это помечено. Выпуск — основной номер (``9.3`` -> ``9``).
"""
from __future__ import annotations

from scanner.feeds.advisories.base import FamilySpec, major
from scanner.feeds.advisories.oval import parse_oval

SPEC = FamilySpec(
    family="rhel", label="Red Hat Enterprise Linux", manager="rpm", parser=parse_oval,
    default_url="https://security.access.redhat.com/data/oval/v2/RHEL{release}/"
                "rhel-{release}.oval.xml.bz2",
    host_families=("rhel", "centos", "rocky", "almalinux", "oracle", "msvsphere"),
    release_of=lambda v, c: major(v), note="OVAL v2 Red Hat (RHSA)")
