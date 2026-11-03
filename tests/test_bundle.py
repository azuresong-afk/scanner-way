"""Комплект данных уязвимостей: сборка, импорт при первой установке, докачка
только изменений после импорта, защита от повреждённого и чужого файла."""
from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select

from scanner.cli import main
from scanner.core.db import Base, FeedSync, make_session_factory, session_scope
from scanner.feeds import bundle as B
from scanner.feeds.advisories.base import Advisory
from scanner.feeds.advisories.store import SqlAdvisoryStore
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.epss import EpssRow, sync_epss
from scanner.feeds.kev import sync_kev
from scanner.feeds.nvd import CpeMatch, NvdRecord
from scanner.feeds.store import (
    SqlReferenceStore,
    epss_score,
    kev,
    nvd_cpe_match,
    nvd_cve,
)
from tests.conftest import PG_URL

NVD_AT = datetime(2026, 11, 1, 3, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def _engine(path: Path):
    eng = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(eng)
    SqlReferenceStore(eng).create_schema()
    return eng


def _populate(eng) -> None:
    store = SqlReferenceStore(eng)
    store.upsert_bdu([
        BduRecord(bdu_id="BDU:2024-00001", title="Уязвимость OpenSSH", software="OpenSSH",
                  cvss_score=8.1, other_ids="CVE-2024-6387", severity_text="Высокий",
                  cve_ids=["CVE-2024-6387"]),
        BduRecord(bdu_id="BDU:2023-00002", title="Уязвимость nginx", software="nginx",
                  other_ids="CVE-2023-44487", cve_ids=["CVE-2023-44487"]),
    ])
    store.upsert_nvd([
        NvdRecord(cve_id="CVE-2024-6387", cvss_v3=8.1, severity="HIGH",
                  summary="regreSSHion «тест»", refs=["https://example.org/a"],
                  cpe=["cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"],
                  cpe_matches=[CpeMatch("CVE-2024-6387",
                                        "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "openbsd", "openssh", version_start_incl="8.5p1",
                                        version_end_excl="9.8p1")],
                  updated_at=NVD_AT - timedelta(days=2)),
        NvdRecord(cve_id="CVE-2023-44487", cvss_v3=7.5, updated_at=NVD_AT - timedelta(days=9)),
    ])
    sync_epss(eng, [EpssRow("CVE-2024-6387", 0.5, 0.97)], "2026-11-01")
    sync_kev(eng, [("CVE-2023-44487", "2023-10-10")])
    SqlAdvisoryStore(eng).replace_release("debian", "bookworm", [
        Advisory("debian", "bookworm", "openssh", "CVE-2024-6387", "fixed",
                 "1:9.2p1-2+deb12u3", "DSA-5724-1")])
    sessions = make_session_factory(eng)
    with session_scope(sessions) as s:
        s.add(FeedSync(source="nvd", enabled=True, last_success_at=NVD_AT,
                       last_result="ok", fingerprint=None))
        s.add(FeedSync(source="epss", enabled=False, last_success_at=NVD_AT,
                       fingerprint="abc123"))


@pytest.fixture
def built(tmp_path):
    src = _engine(tmp_path / "src.db")
    _populate(src)
    nuclei = tmp_path / "nuclei"
    (nuclei / "http" / "cves").mkdir(parents=True)
    (nuclei / "http" / "cves" / "CVE-2024-0001.yaml").write_text("id: t\n")
    res = B.export_bundle(src, tmp_path / "out" / "scanner-data-20261103.tar",
                          nuclei_dir=nuclei, scanner_version="0.1.0", now=NOW)
    src.dispose()
    return res


def _count(eng, table) -> int:
    with eng.connect() as c:
        return c.scalar(select(func.count()).select_from(table))


def _feed(eng, source) -> FeedSync:
    sessions = make_session_factory(eng)
    with session_scope(sessions) as s:
        row = s.get(FeedSync, source)
        s.expunge(row)
        return row


def test_export_manifest_lists_sources_with_dates(built):
    m = built.manifest
    assert set(m["sources"]) == {"bdu", "nvd", "epss", "kev", "advisories"}
    assert "msrc" in built.skipped                     # нет данных — не в комплекте
    assert m["sources"]["nvd"]["as_of"].startswith("2026-11-01T03:00")   # из feed_sync
    assert m["sources"]["kev"]["as_of"].startswith("2026-11-03")         # момент сборки
    assert m["sources"]["epss"]["fingerprint"] == "abc123"
    assert m["sources"]["advisories"]["releases"] == ["debian:bookworm"]
    assert m["nuclei_templates"]["count"] == 1
    with tarfile.open(built.path) as t:
        names = t.getnames()
        assert names[0] == "manifest.json"             # читается без листания всего файла
        notice = t.extractfile("NOTICE.txt").read().decode()
    assert "not endorsed or certified by the NVD" in notice
    assert "FIRST" in notice and "MIT" in notice
    assert not list(built.path.parent.glob("*.part"))


def test_nvd_as_of_falls_back_to_latest_change(tmp_path):
    eng = _engine(tmp_path / "s.db")
    SqlReferenceStore(eng).upsert_nvd([
        NvdRecord(cve_id="CVE-2024-1", updated_at=datetime(2026, 10, 20, tzinfo=UTC))])
    res = B.export_bundle(eng, tmp_path / "b.tar", now=NOW)
    # загружено через CLI — даты в feed_sync нет: граница = последнее изменение CVE
    assert res.manifest["sources"]["nvd"]["as_of"].startswith("2026-10-20")


def test_import_into_empty_install(built, tmp_path):
    dst = _engine(tmp_path / "dst.db")
    templates = tmp_path / "dst-nuclei"
    results = B.import_bundle(dst, built.path, nuclei_dir=templates, now=NOW)
    by = {r.source: r for r in results}
    assert {s for s, r in by.items() if r.status == "imported"} == {
        "bdu", "nvd", "epss", "kev", "advisories", "nuclei"}
    assert _count(dst, nvd_cve) == 2 and _count(dst, nvd_cpe_match) == 1
    assert _count(dst, epss_score) == 1 and _count(dst, kev) == 1
    store = SqlReferenceStore(dst)
    rec = store.get_nvd("CVE-2024-6387")
    assert rec.summary == "regreSSHion «тест»" and rec.refs == ["https://example.org/a"]
    assert float(rec.cvss_v3) == 8.1
    assert rec.updated_at.date() == (NVD_AT - timedelta(days=2)).date()
    assert [b.bdu_id for b in store.bdu_by_cve("CVE-2024-6387")] == ["BDU:2024-00001"]
    m = store.cpe_matches("openssh")
    assert m and m[0].version_end_excl == "9.8p1"
    adv = SqlAdvisoryStore(dst).for_packages("debian", "bookworm", ["openssh"])
    assert adv["openssh"][0].fixed_version == "1:9.2p1-2+deb12u3"
    assert (templates / "http" / "cves" / "CVE-2024-0001.yaml").is_file()

    nvd = _feed(dst, "nvd")
    assert nvd.last_success_at.replace(tzinfo=UTC) == NVD_AT
    assert nvd.enabled is False                        # расписание не включается само
    assert "Из комплекта данных от 03.11.2026" in nvd.message
    assert _feed(dst, "epss").fingerprint == "abc123"


def test_second_start_skips_up_to_date_sources(built, tmp_path):
    dst = _engine(tmp_path / "dst.db")
    B.import_bundle(dst, built.path, now=NOW)
    again = B.import_bundle(dst, built.path, now=NOW)
    assert all(r.status == "skipped" for r in again)
    forced = B.import_bundle(dst, built.path, sources=["kev"], force=True, now=NOW)
    assert [(r.source, r.status) for r in forced] == [("kev", "imported")]
    assert _count(dst, kev) == 1                       # заменено, а не задвоено


def test_manual_data_is_not_overwritten(built, tmp_path):
    dst = _engine(tmp_path / "dst.db")
    sync_kev(dst, [("CVE-2099-1", None), ("CVE-2099-2", None)])   # грузили руками
    res = {r.source: r for r in B.import_bundle(dst, built.path, now=NOW)}
    assert res["kev"].status == "skipped" and res["nvd"].status == "imported"
    assert _count(dst, kev) == 2


def test_older_local_data_is_replaced(built, tmp_path):
    dst = _engine(tmp_path / "dst.db")
    sync_kev(dst, [("CVE-2099-1", None)])
    sessions = make_session_factory(dst)
    with session_scope(sessions) as s:
        s.add(FeedSync(source="kev", last_success_at=NVD_AT - timedelta(days=30)))
    res = {r.source: r for r in B.import_bundle(dst, built.path, now=NOW)}
    assert res["kev"].status == "imported"
    with dst.connect() as c:
        assert c.scalar(select(kev.c.cve)) == "CVE-2023-44487"


def test_after_import_nvd_downloads_only_changes(built, tmp_path, monkeypatch):
    """Главное: после импорта NVD не качается с нуля, а с даты комплекта."""
    from scanner.feeds import nvd as nvd_mod
    from scanner.feeds.sources import NVD_OVERLAP, FeedContext, load_nvd

    dst = _engine(tmp_path / "dst.db")
    B.import_bundle(dst, built.path, now=NOW)
    calls = []

    def fake_iter_api(self, *, last_mod_start=None, last_mod_end=None):
        calls.append((last_mod_start, last_mod_end))
        return iter([])

    monkeypatch.setattr(nvd_mod.NvdFeed, "iter_api", fake_iter_api)
    feed = _feed(dst, "nvd")
    load_nvd(FeedContext(engine=dst, audit=None, now=NOW,
                         last_success_at=feed.last_success_at.replace(tzinfo=UTC)))
    assert calls and calls[0][0] == NVD_AT - NVD_OVERLAP     # не полная выгрузка
    assert calls[-1][1] == NOW


def test_corrupted_bundle_leaves_data_untouched(built, tmp_path):
    dst = _engine(tmp_path / "dst.db")
    sync_kev(dst, [("CVE-2099-1", None)])
    sessions = make_session_factory(dst)
    with session_scope(sessions) as s:
        s.add(FeedSync(source="kev", last_success_at=datetime(2020, 1, 1, tzinfo=UTC)))
    bad = tmp_path / "scanner-data-bad.tar"
    with tarfile.open(built.path) as src, tarfile.open(bad, "w") as out:
        for m in src.getmembers():
            data = src.extractfile(m).read()
            if m.name == "data/kev.jsonl.gz":
                data = data[:-4] + b"\0\0\0\0"
            m.size = len(data)
            out.addfile(m, io.BytesIO(data))
    with pytest.raises(B.BundleError, match="контрольная сумма"):
        B.import_bundle(dst, bad, sources=["kev"], now=NOW)
    with dst.connect() as c:
        assert c.scalar(select(kev.c.cve)) == "CVE-2099-1"


def _tar_with_manifest(path: Path, manifest: dict) -> Path:
    data = json.dumps(manifest).encode()
    with tarfile.open(path, "w") as t:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return path


def test_foreign_or_newer_format_is_rejected(tmp_path):
    with pytest.raises(B.BundleError, match="не комплект"):
        B.read_manifest(_tar_with_manifest(tmp_path / "a.tar", {"kind": "other"}))
    with pytest.raises(B.BundleError, match="обновите сканер"):
        B.read_manifest(_tar_with_manifest(tmp_path / "b.tar",
                                           {"kind": B.KIND, "format": B.FORMAT + 1}))
    (tmp_path / "c.tar").write_bytes(b"not a tar")
    with pytest.raises(B.BundleError):
        B.read_manifest(tmp_path / "c.tar")


def test_nuclei_archive_cannot_escape_target(tmp_path):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as t:
        for name in ("nuclei-templates/ok.yaml", "nuclei-templates/../../evil.yaml",
                     "/etc/evil.yaml", "other/evil.yaml"):
            info = tarfile.TarInfo(name)
            info.size = 3
            t.addfile(info, io.BytesIO(b"x: "))
        link = tarfile.TarInfo("nuclei-templates/link.yaml")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        t.addfile(link)
    data = payload.getvalue()
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as t:
        info = tarfile.TarInfo(B.NUCLEI_MEMBER)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    outer.seek(0)
    import hashlib
    dest = tmp_path / "x" / "templates"
    with tarfile.open(fileobj=outer) as t:
        r = B._import_nuclei(t, {"path": B.NUCLEI_MEMBER,
                                 "sha256": hashlib.sha256(data).hexdigest()}, dest, False)
    assert r.count == 1
    assert sorted(p.name for p in tmp_path.rglob("*.yaml")) == ["ok.yaml"]


def test_find_bundle_picks_newest(built, tmp_path):
    d = tmp_path / "bundles"
    d.mkdir()
    old = d / "scanner-data-20250101.tar"
    _tar_with_manifest(old, {"kind": B.KIND, "format": 1,
                             "created_at": "2025-01-01T00:00:00+00:00", "sources": {}})
    new = d / "scanner-data-20261103.tar"
    new.write_bytes(built.path.read_bytes())
    (d / "scanner-data-broken.tar").write_bytes(b"junk")
    assert B.find_bundle([tmp_path / "missing", d]) == new
    assert B.find_bundle([tmp_path / "missing"]) is None


def test_cli_export_info_import(tmp_path, capsys):
    src_db = tmp_path / "src.db"
    _populate(_engine(src_db))
    out = tmp_path / "bundle" / "scanner-data-20261103.tar"
    assert main(["--db-url", f"sqlite:///{src_db}", "bundle", "export", "--out", str(out),
                 "--no-nuclei"]) == 0
    assert "комплект:" in capsys.readouterr().out
    assert main(["--db-url", f"sqlite:///{src_db}", "bundle", "info", str(out)]) == 0
    assert "debian:bookworm" in capsys.readouterr().out

    dst_db = tmp_path / "dst.db"
    # --auto без комплекта — не ошибка (обычная установка без поставки данных)
    assert main(["--db-url", f"sqlite:///{dst_db}", "bundle", "import", "--auto",
                 "--dir", str(tmp_path / "none")]) == 0
    assert main(["--db-url", f"sqlite:///{dst_db}", "bundle", "import", "--auto",
                 "--dir", str(out.parent), "--nuclei-templates",
                 str(tmp_path / "t")]) == 0
    printed = capsys.readouterr().out
    assert "nvd: загружено" in printed
    eng = create_engine(f"sqlite:///{dst_db}")
    assert _count(eng, nvd_cve) == 2
    # без --auto отсутствие комплекта — ошибка с понятной причиной
    assert main(["--db-url", f"sqlite:///{dst_db}", "bundle", "import",
                 "--dir", str(tmp_path / "none")]) == 2


# ---------- PostgreSQL (CI): массивы, Numeric, даты с поясом ----------
@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_pg_export_import_round_trip(tmp_path):
    from alembic import command
    from scanner.core.db import make_engine
    from tests.test_migrations_pg import _alembic_cfg

    cfg = _alembic_cfg()
    command.upgrade(cfg, "head")
    eng = make_engine(PG_URL)
    try:
        _populate(eng)
        res = B.export_bundle(eng, tmp_path / "scanner-data-pg.tar", now=NOW)
        # PG → SQLite: чистая установка на другой СУБД
        lite = _engine(tmp_path / "lite.db")
        B.import_bundle(lite, res.path, now=NOW)
        assert [b.bdu_id for b in SqlReferenceStore(lite).bdu_by_cve("CVE-2024-6387")] \
            == ["BDU:2024-00001"]
        # PG ← комплект поверх своих данных (force): массивы и даты сохраняются
        out = B.import_bundle(eng, res.path, force=True, now=NOW)
        assert {r.source for r in out if r.status == "imported"} >= {"nvd", "bdu"}
        store = SqlReferenceStore(eng)
        rec = store.get_nvd("CVE-2024-6387")
        assert rec.refs == ["https://example.org/a"] and float(rec.cvss_v3) == 8.1
        assert [b.bdu_id for b in store.bdu_by_cve("CVE-2024-6387")] == ["BDU:2024-00001"]
        assert _feed(eng, "nvd").last_success_at == NVD_AT
    finally:
        eng.dispose()
        command.downgrade(cfg, "base")


def test_cli_feeds_sync_records_date_for_bundle(tmp_path, monkeypatch, capsys):
    """`feeds sync` пишет итог в feed_sync, как автообновление: комплект берёт
    оттуда «актуально на», а повторная загрузка того же файла пропускается."""
    from scanner.core.config import settings

    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2023-44487", "dateAdded": "2023-10-10"}]}))
    monkeypatch.setattr(settings, "kev_feed_path", str(kev_file))
    db = f"sqlite:///{tmp_path / 'x.db'}"
    assert main(["--db-url", db, "feeds", "sync", "kev"]) == 0
    assert "kev: ok" in capsys.readouterr().out
    assert main(["--db-url", db, "feeds", "sync", "kev"]) == 0
    assert "kev: unchanged" in capsys.readouterr().out
    eng = create_engine(db)
    row = _feed(eng, "kev")
    assert row.last_success_at is not None and row.fingerprint
    assert main(["--db-url", db, "feeds", "sync", "nope"]) == 2
