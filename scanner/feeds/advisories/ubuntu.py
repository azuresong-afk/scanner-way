"""Ubuntu: OVAL бюллетеней USN (security-metadata.canonical.com), файл на выпуск.

Имена пакетов в OVAL — бинарные (``libssl3``, ``openssh-server``).
"""
from __future__ import annotations

from scanner.feeds.advisories.base import FamilySpec
from scanner.feeds.advisories.oval import parse_oval

CODENAMES = {"16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy",
             "24.04": "noble", "24.10": "oracular", "25.04": "plucky"}


def release_of(version_id: str | None, codename: str | None) -> str | None:
    if codename and codename.strip():
        return codename.strip().lower()
    return CODENAMES.get((version_id or "").strip())


SPEC = FamilySpec(
    family="ubuntu", label="Ubuntu", manager="dpkg", parser=parse_oval,
    default_url="https://security-metadata.canonical.com/oval/"
                "com.ubuntu.{release}.usn.oval.xml.bz2",
    host_families=("ubuntu",), release_of=release_of, note="OVAL бюллетеней USN")
