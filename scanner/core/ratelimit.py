"""Профили интенсивности и лимиты скорости/параллелизма.

Защита от DoS и блокировок аккаунтов. Для cred audit лимиты жёстче (см. профиль
и отдельные поля max_auth_attempts_per_target).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateProfile:
    name: str
    max_requests_per_sec: float
    max_concurrency: int
    delay_between_attempts_sec: float
    # Отдельно для credential audit:
    max_auth_attempts_per_target: int
    backoff_factor: float


PROFILES: dict[str, RateProfile] = {
    "gentle": RateProfile("gentle", 5, 8, 0.5, 3, 2.0),
    "normal": RateProfile("normal", 20, 32, 0.2, 5, 2.0),
    "aggressive": RateProfile("aggressive", 100, 128, 0.0, 8, 1.5),
}


def get_profile(name: str) -> RateProfile:
    return PROFILES.get(name, PROFILES["gentle"])
