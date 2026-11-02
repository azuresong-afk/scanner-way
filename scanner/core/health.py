"""Проверки работоспособности для оркестратора контейнеров и мониторинга.

* живость (`GET /health`) — процесс API отвечает; БД не трогается, чтобы
  краткий сбой PostgreSQL не приводил к перезапуску API;
* готовность (`GET /health/ready`) — БД доступна и схема на последней
  миграции Alembic (иначе часть запросов упадёт на отсутствующих колонках),
  плюс фоновые потоки API (прогоны, расписания, справочники, уведомления).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine

ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def expected_revision() -> str | None:
    """Головная ревизия Alembic из файлов миграций (None — каталога нет)."""
    script_dir = ROOT / "alembic"
    if not script_dir.is_dir():
        return None
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config()
    cfg.set_main_option("script_location", str(script_dir))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    return heads[0] if len(heads) == 1 else None


def check_database(engine: Engine, *, check_migrations: bool = True) -> dict[str, object]:
    """{"database": "ok"|"error", "migration": ревизия, "expected": голова, "error": ...}."""
    out: dict[str, object] = {}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            out["database"] = "ok"
            if check_migrations:
                try:
                    rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                except Exception:  # noqa: BLE001 — нет таблицы: схема не из Alembic
                    rev = None
                out["migration"] = rev
                out["expected"] = expected_revision()
    except Exception as e:  # noqa: BLE001 — отдаём причину в ответе проверки
        out["database"] = "error"
        out["error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
    return out


def is_ready(db: dict[str, object], threads: dict[str, bool]) -> bool:
    if db.get("database") != "ok":
        return False
    if "expected" in db and db.get("expected") is not None \
            and db.get("migration") != db.get("expected"):
        return False
    return all(threads.values())
