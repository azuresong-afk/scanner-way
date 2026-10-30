"""Страж цепочки миграций Alembic (R0, docs/roadmap-v2.md, раздел 4.1).

Проверяет только файлы ревизий и граф, PostgreSQL не нужен. Цель — чтобы
параллельные PR не занимали один и тот же номер миграции и не строили две головы.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError

ROOT = Path(__file__).resolve().parents[1]
HINT = "см. docs/roadmap-v2.md, раздел 4.1"


def _load():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    script = ScriptDirectory.from_config(cfg)
    try:
        revs = list(script.walk_revisions("base", "heads"))
    except RevisionError as exc:
        pytest.fail(f"Цепочка миграций сломана: {exc}. Номер занят / пропущен — {HINT}", pytrace=False)
    return script, revs


def test_single_head():
    script, _ = _load()
    heads = sorted(script.get_heads())
    assert len(heads) == 1, (
        f"Несколько голов миграций {heads}: две ветки от одной ревизии. "
        f"Номер занят / пропущен — {HINT}"
    )


def test_revision_matches_filename_and_sequence():
    _, revs = _load()
    by_number: dict[str, str] = {}
    for rev in revs:
        name = Path(rev.path).name
        prefix = name[:4]
        assert re.fullmatch(r"\d{4}", prefix) and name[4:5] == "_", (
            f"Файл {name}: имя должно начинаться с четырёхзначного номера и «_». {HINT}"
        )
        assert rev.revision == prefix, (
            f"Файл {name}: revision = {rev.revision!r}, а номер в имени — {prefix}. "
            f"Номер занят / пропущен — {HINT}"
        )
        assert prefix not in by_number, (
            f"Номер занят: файлы {by_number.get(prefix)} и {name} оба с номером {prefix}. {HINT}"
        )
        by_number[prefix] = name

    numbers = sorted(int(p) for p in by_number)
    expected = list(range(1, len(numbers) + 1))
    missing = sorted(set(expected) - set(numbers))
    assert numbers == expected, (
        f"Номер пропущен: нет миграций с номерами {[f'{n:04d}' for n in missing]}. {HINT}"
    )


def test_down_revision_is_previous_number():
    _, revs = _load()
    for rev in revs:
        number = int(rev.revision)
        expected = None if number == 1 else f"{number - 1:04d}"
        assert rev.down_revision == expected, (
            f"Файл {Path(rev.path).name}: down_revision = {rev.down_revision!r}, "
            f"ожидался {expected!r}. Номер занят / пропущен — {HINT}"
        )
