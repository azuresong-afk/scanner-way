"""CLI: разбор аргументов, загрузка БДУ в справочник, прогон и отчёт на SQLite.

Без сети и без внешних движков: БДУ — маленький XLSX в формате выгрузки,
модули прогона — фиктивные.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from sqlalchemy import create_engine, select

from scanner import cli
from scanner.core import repository as repo
from scanner.core.db import AuditLogRow, make_session_factory, session_scope
from scanner.core.models import Finding, FindingType, ServiceInfo, Severity
from scanner.feeds.store import SqlReferenceStore
from scanner.modules.base import ScanContext, ScanModule
from tests.conftest import PG_URL
from tests.test_bdu_parser import HEADER

ROOT = Path(__file__).resolve().parents[1]


# ---------- фикстуры ----------
@pytest.fixture
def db_url(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'scanner.db'}"


@pytest.fixture
def bdu_xlsx(tmp_path) -> Path:
    """XLSX с раскладкой реальной выгрузки: 2 групповые строки, шапка, данные."""
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Уязвимости"
    ws.append(["Описание уязвимостей"])
    ws.append(["Общая информация"])
    ws.append(HEADER)

    def row(bdu_id, cves, severity, remediation):
        r = [None] * len(HEADER)
        r[0], r[1], r[4], r[5] = bdu_id, "Уязвимость OpenSSH", "OpenSSH", "до 7.5 (OpenSSH)"
        r[13], r[14], r[19] = severity, remediation, cves
        return r

    ws.append(row("BDU:2017-00001", "CVE-2016-10009, CVE-2016-10010",
                  "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,5)",
                  "Обновление программного обеспечения до версии 7.5"))
    ws.append(row("BDU:2019-00002", "CVE-2018-15473",
                  "Средний уровень опасности (базовая оценка CVSS 3.0 составляет 5,3)",
                  "Использование рекомендаций производителя"))
    path = tmp_path / "vullist.xlsx"
    wb.save(path)
    return path


def _audit(url: str, action: str) -> list[AuditLogRow]:
    engine = create_engine(url)
    with make_session_factory(engine)() as s:
        rows = list(s.scalars(select(AuditLogRow).where(AuditLogRow.action == action)))
    engine.dispose()
    return rows


# ---------- разбор аргументов ----------
def test_parse_sync_bdu():
    a = cli.build_parser().parse_args(
        ["--db-url", "sqlite://", "feeds", "sync-bdu", "--file", "/data/vullist.xlsx"])
    assert a.handler is cli.cmd_sync_bdu
    assert a.file == Path("/data/vullist.xlsx") and a.batch_size == 1000
    assert a.db_url == "sqlite://" and a.actor.startswith("cli:")


def test_parse_sync_bdu_requires_file(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["feeds", "sync-bdu"])


def test_parse_sync_nvd_files_and_period():
    a = cli.build_parser().parse_args(
        ["feeds", "sync-nvd", "--file", "a.json", "--file", "b.json.gz"])
    assert a.handler is cli.cmd_sync_nvd and a.files == [Path("a.json"), Path("b.json.gz")]
    a = cli.build_parser().parse_args(
        ["feeds", "sync-nvd", "--since", "2026-09-01", "--until", "2026-10-01T00:00:00+00:00"])
    assert a.files == [] and a.since.tzinfo is not None and a.until.year == 2026


def test_parse_run():
    a = cli.build_parser().parse_args(
        ["--actor", "anton", "run", "--engagement", "3", "--targets", "10.0.0.0/30",
         "10.0.0.9", "--modules", "vuln", "discovery", "--rate", "normal",
         "--confirm-authorized"])
    assert a.handler is cli.cmd_run and a.engagement == 3
    assert a.targets == ["10.0.0.0/30", "10.0.0.9"]
    assert a.modules == ["vuln", "discovery"] and a.rate == "normal"
    assert a.confirm_authorized and not a.allow_cred_audit and a.actor == "anton"


def test_parse_run_defaults_and_rejects_unknown():
    a = cli.build_parser().parse_args(["run", "--engagement", "1", "--targets", "10.0.0.1"])
    assert a.modules == ["discovery", "vuln"] and a.rate == "gentle"
    assert not a.confirm_authorized
    for bad in (["--modules", "exploit"], ["--rate", "insane"]):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(
                ["run", "--engagement", "1", "--targets", "10.0.0.1", *bad])


def test_parse_report():
    a = cli.build_parser().parse_args(["report", "--run", "7", "--format", "docx"])
    assert a.handler is cli.cmd_report and a.run_id == 7 and a.format == "docx"
    assert a.out is None and not a.no_compare
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["report", "--run", "7", "--format", "xls"])


def test_command_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


# ---------- feeds ----------
def test_sync_bdu_loads_records_into_store(db_url, bdu_xlsx, capsys):
    rc = cli.main(["--db-url", db_url, "--actor", "tester",
                   "feeds", "sync-bdu", "--file", str(bdu_xlsx)])
    assert rc == 0
    assert "загружено записей — 2" in capsys.readouterr().out

    store = SqlReferenceStore(create_engine(db_url))
    rec = store.get_bdu("BDU:2017-00001")
    assert rec is not None and rec.cvss_score == 7.5
    assert rec.cve_ids == ["CVE-2016-10009", "CVE-2016-10010"]
    assert rec.remediation.startswith("Обновление")
    assert [r.bdu_id for r in store.bdu_by_cve("CVE-2018-15473")] == ["BDU:2019-00002"]
    store.engine.dispose()

    [row] = _audit(db_url, "feed_sync")
    assert (row.subject, row.target, row.result) == ("tester", "bdu_fstec", "ok")
    assert row.details["records"] == 2

    # повторная загрузка обновляет по bdu_id, не дублирует
    assert cli.main(["--db-url", db_url, "feeds", "sync-bdu", "--file", str(bdu_xlsx)]) == 0
    assert "загружено записей — 2" in capsys.readouterr().out


def test_sync_bdu_missing_file(db_url, tmp_path, capsys):
    rc = cli.main(["--db-url", db_url, "feeds", "sync-bdu",
                   "--file", str(tmp_path / "nope.xlsx")])
    assert rc == 2 and "файл не найден" in capsys.readouterr().err


def test_sync_nvd_offline_file(db_url, tmp_path, capsys):
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2018-15473",
        "descriptions": [{"lang": "en", "value": "OpenSSH user enumeration"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 5.3, "baseSeverity": "MEDIUM",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "versionEndIncluding": "7.7"}]}]}],
        "references": [{"url": "https://example.org/adv"}]}}]}
    path = tmp_path / "nvdcve-2.0-2018.json"
    path.write_text(json.dumps(feed), encoding="utf-8")

    assert cli.main(["--db-url", db_url, "feeds", "sync-nvd", "--file", str(path)]) == 0
    assert "загружено CVE — 1" in capsys.readouterr().out
    store = SqlReferenceStore(create_engine(db_url))
    rec = store.get_nvd("CVE-2018-15473")
    assert rec is not None and rec.cvss_v3 == 5.3
    assert [m.product for m in store.cpe_matches("openssh")] == ["openssh"]
    store.engine.dispose()


def test_sync_nvd_rejects_mixed_sources(db_url, capsys):
    rc = cli.main(["--db-url", db_url, "feeds", "sync-nvd", "--file", "x.json",
                   "--cve", "CVE-2018-15473"])
    assert rc == 2 and "--file нельзя" in capsys.readouterr().err


# ---------- run / report ----------
class FakeDiscovery(ScanModule):
    name = "discovery"

    def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.services = [ServiceInfo(t, 22, "tcp", "ssh", "OpenSSH", "7.4") for t in ctx.targets]
        return []


class FakeVuln(ScanModule):
    name = "vuln"
    seen: ClassVar[list[str]] = []

    def run(self, ctx: ScanContext) -> list[Finding]:
        FakeVuln.seen = list(ctx.targets)
        return [Finding(module=self.name, host=s.host, port=s.port,
                        finding_type=FindingType.VULN, title="OpenSSH user enumeration",
                        severity=Severity.MEDIUM, vuln_id="CVE-2018-15473",
                        cve_ids=["CVE-2018-15473"], bdu_ids=["BDU:2019-00002"], cvss=5.3)
                for s in ctx.services]


REGISTRY = {"discovery": FakeDiscovery, "vuln": FakeVuln}


@pytest.fixture
def engagement(db_url) -> tuple[str, int]:
    """Договор с allowlist 10.10.0.0/30 в SQLite-файле, схема — через CLI."""
    args = cli.build_parser().parse_args(["--db-url", db_url, "report", "--run", "0"])
    env = cli._Env(args)
    with session_scope(env.sessions) as s:
        eid = repo.create_engagement(s, name="Пилот", client="ООО Заказчик",
                                     contract_ref="Договор №42")
        repo.add_allowlist_entry(s, engagement_id=eid, cidr="10.10.0.0/30")
    env.engine.dispose()
    return db_url, eid


def _run(db_url: str, *extra: str) -> tuple[int, cli._Env]:
    args = cli.build_parser().parse_args(["--db-url", db_url, "--actor", "tester", "run",
                                          *extra])
    env = cli._Env(args)
    try:
        return cli.cmd_run(args, env, registry=REGISTRY), env
    finally:
        env.engine.dispose()


def test_run_requires_authorization_flag(engagement):
    url, eid = engagement
    with pytest.raises(cli.CliError, match="--confirm-authorized"):
        _run(url, "--engagement", str(eid), "--targets", "10.10.0.1")


def test_run_requires_cred_audit_flag(engagement):
    url, eid = engagement
    with pytest.raises(cli.CliError, match="--allow-cred-audit"):
        _run(url, "--engagement", str(eid), "--targets", "10.10.0.1",
             "--modules", "cred_audit", "--confirm-authorized")


def test_run_unknown_engagement(db_url):
    with pytest.raises(cli.CliError, match="не найден"):
        _run(db_url, "--engagement", "999", "--targets", "10.10.0.1", "--confirm-authorized")


def test_run_refuses_targets_outside_allowlist(engagement):
    url, eid = engagement
    with pytest.raises(cli.CliError, match="allowlist"):
        _run(url, "--engagement", str(eid), "--targets", "192.168.1.1",
             "--confirm-authorized")
    [row] = _audit(url, "scan_queue")
    assert row.result == "denied"


def test_run_and_report(engagement, tmp_path, capsys):
    url, eid = engagement
    # вторая цель вне allowlist — отбрасывается гейтом, прогон идёт по остальным
    rc, _ = _run(url, "--engagement", str(eid), "--targets", "10.10.0.0/30",
                 "203.0.113.5", "--confirm-authorized")
    out = capsys.readouterr()
    assert rc == 0 and "done" in out.out and "203.0.113.5" in out.err
    assert FakeVuln.seen == ["10.10.0.1", "10.10.0.2"]
    assert {r.result for r in _audit(url, "deny")} == {"not_in_allowlist"}

    report_path = tmp_path / "out" / "report.json"
    assert cli.main(["--db-url", url, "report", "--run", "1", "--format", "json",
                     "--out", str(report_path)]) == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["meta"]["engagement"] == "Договор №42"
    assert len(data["combined"]["findings"]) == 2
    [exp] = _audit(url, "export")
    assert exp.target == "scan_run:1" and exp.details["format"] == "json"

    assert cli.main(["--db-url", url, "report", "--run", "1", "--format", "html",
                     "--out", str(tmp_path / "r.html")]) == 0
    assert "CVE-2018-15473" in (tmp_path / "r.html").read_text(encoding="utf-8")


def test_report_unknown_run(db_url, capsys):
    assert cli.main(["--db-url", db_url, "report", "--run", "5"]) == 2
    assert "не найден" in capsys.readouterr().err


# ---------- Postgres: схема через Alembic ----------
@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_sync_bdu_on_postgres_applies_migrations(bdu_xlsx):
    from alembic.config import Config

    from alembic import command

    try:
        assert cli.main(["--db-url", PG_URL, "feeds", "sync-bdu",
                         "--file", str(bdu_xlsx)]) == 0
        store = SqlReferenceStore(create_engine(PG_URL))
        assert [r.bdu_id for r in store.bdu_by_cve("CVE-2016-10010")] == ["BDU:2017-00001"]
        store.engine.dispose()
    finally:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", PG_URL)
        command.downgrade(cfg, "base")
