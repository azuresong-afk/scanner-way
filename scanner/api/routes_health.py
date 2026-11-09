"""Страница «Состояние»: подробный хелсчек самого сканера для вошедших пользователей.

Без входа доступны только `/health` (живость), `/health/ready` (готовность) и
`/health/status` (статусы компонентов без подробностей) — см. scanner.api.main.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from scanner.api.deps import CurrentUser

router = APIRouter(tags=["health"])


@router.get("/system/health")
def system_health(request: Request, user: CurrentUser, refresh: bool = False) -> dict:
    """Состояние компонентов: БД, фоновые службы, прогоны, движки, справочники,
    диск, узлы-сканеры, уведомления — со статусом, сводкой и подсказкой.
    refresh=true — проверить заново, минуя кэш (и перечитать версии движков)."""
    return request.app.state.health.report(refresh=refresh)
