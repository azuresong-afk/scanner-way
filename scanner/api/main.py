"""FastAPI-слой: запуск прогонов, отчёты, RBAC. Каркас — заглушки эндпоинтов."""
from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Scanner", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# TODO (итерация 5): эндпоинты engagements/allowlist, запуск/остановка прогона,
# получение отчётов; RBAC-зависимости (admin/operator/auditor + право cred_audit).
