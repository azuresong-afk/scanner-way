"""Шаблоны Nuclei для узлов: центр раздаёт свою копию, узел её забирает.

Узел в изолированном сегменте обычно не видит GitHub, но видит центр. Центр
упаковывает свой каталог шаблонов (scanner.feeds.sources.nuclei_templates_dir)
в tar.gz с отпечатком (ETag); узел при старте и раз в сутки спрашивает, не
изменился ли он, и распаковывает новый архив во временный каталог, после чего
подменяет им свой (прогон, идущий в этот момент, не увидит половины шаблонов).
Распаковка — только обычные файлы и каталоги внутри целевого каталога.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
import threading
from pathlib import Path

_lock = threading.Lock()


def fingerprint(directory: Path) -> str | None:
    """Отпечаток каталога: число файлов, размеры и последние изменения."""
    if not directory.is_dir():
        return None
    h = hashlib.sha256()
    n = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".git"))
        for f in sorted(files):
            if not f.endswith((".yaml", ".yml", ".json", ".txt")):
                continue
            p = Path(root, f)
            try:
                st = p.stat()
            except OSError:
                continue
            h.update(f"{p.relative_to(directory)}:{st.st_size}:{int(st.st_mtime)}\n".encode())
            n += 1
    return f"{n}-{h.hexdigest()[:24]}" if n else None


def build_archive(directory: Path, cache_dir: Path | None = None) -> tuple[Path, str] | None:
    """(архив, ETag) — из кэша, если каталог не изменился. None — шаблонов нет."""
    fp = fingerprint(directory)
    if fp is None:
        return None
    cache = Path(cache_dir or tempfile.gettempdir()) / "scanner-node-templates"
    out = cache / f"nuclei-templates-{fp}.tar.gz"
    with _lock:
        if not out.is_file():
            cache.mkdir(parents=True, exist_ok=True)
            for old in cache.glob("nuclei-templates-*.tar.gz"):
                old.unlink(missing_ok=True)
            tmp = out.with_suffix(".part")
            with tarfile.open(tmp, "w:gz", compresslevel=6) as tar:
                for root, dirs, files in os.walk(directory):
                    dirs[:] = sorted(d for d in dirs if not d.startswith(".git"))
                    for f in sorted(files):
                        p = Path(root, f)
                        if p.is_symlink() or not p.is_file():
                            continue
                        tar.add(p, arcname=str(p.relative_to(directory)), recursive=False)
            tmp.replace(out)
    return out, fp


def install_archive(archive: Path, target: Path) -> int:
    """Распаковывает архив шаблонов в target (через временный каталог рядом).
    -> число файлов. Ссылки, устройства и выход за каталог отбрасываются."""
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".nuclei-new-", dir=target.parent))
    count = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar.getmembers():
                if not (m.isfile() or m.isdir()):
                    continue
                dest = (staging / m.name).resolve()
                if staging.resolve() not in dest.parents and dest != staging.resolve():
                    continue
                if m.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(m)
                if src is None:
                    continue
                with src, open(dest, "wb") as fh:
                    shutil.copyfileobj(src, fh)
                count += 1
        old = None
        if target.exists():
            old = target.with_name(f".nuclei-old-{os.getpid()}")
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)
            target.rename(old)
        staging.rename(target)
        if old is not None:
            shutil.rmtree(old, ignore_errors=True)
        return count
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
