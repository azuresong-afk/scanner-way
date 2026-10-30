"""I1: сквозной прогон волны 1 через API — без сети, на реальных модулях.

Цепочка, которую проверяет тест:
  R12 справочник БДУ загружается планировщиком (настоящий load_bdu из xlsx) ->
  discovery -> auth_inventory по учётке (БДУ/CVE) -> config_audit по учётке (R1a)
  -> password_policy на конфигурации, которую собрал config_audit -> cred_audit
  на наборе проверки (R1b) -> отчёт по группе активов (R7).

Транспорт SSH и проверка входов подменены фейками (те же, что в юнит-тестах
модулей); всё остальное — настоящие модули, оркестратор, БД и отчёт. Отдельно
проверяется, что ни один модуль волны 1 не уходит в `no_credentials`, а секреты
не попадают в журнал, находки и отчёт.
"""
from __future__ import annotations

import json

import openpyxl
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.config import settings as core_settings
from scanner.core.db import AuditLogRow
from scanner.core.orchestrator import inline_executor
from scanner.feeds.matcher import VulnMatcher
from scanner.feeds.nvd import parse_cve_item
from scanner.feeds.sources import FeedSource, load_bdu
from scanner.feeds.store import SqlReferenceStore
from scanner.modules.auth_inventory import AuthInventoryModule
from scanner.modules.base import ScanContext, ScanModule
from scanner.modules.config_audit import ConfigAuditModule, ConfigAuditOptions
from scanner.modules.cred_audit import AuthOutcome, AuthResult, CredentialAuditModule
from scanner.modules.password_policy import PasswordPolicyModule
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import PASSWORD, SECRET, Api, FakeDiscovery, Recorder
from tests.test_auth_inventory import DPKG_OUT
from tests.test_auth_inventory import FakeShell as DpkgShell
from tests.test_bdu_parser import HEADER
from tests.test_config_audit import DS, RULE, FakeNet
from tests.test_matcher import nvd_item

HOST = "10.0.0.5"
HOST_PASSWORD = "Host-Pa55-wave1-no-leak"


class _InertModule(ScanModule):
    """win_inventory-заглушка: без WinRM-учётки находок нет."""
    name = "win_inventory"

    def run(self, ctx: ScanContext) -> list:
        return []
SET_SECRET = "Set-Pa55-wave1-no-leak"
# Политика хоста: длина 6 (< 8), срок 99999 дней, сложность не задана,
# блокировка после 5 неудачных входов настроена.
POLICY = ("@@scanner-policy-file /etc/login.defs\nPASS_MAX_DAYS 99999\nPASS_MIN_LEN 6\n\n"
          "@@scanner-policy-file /etc/security/faillock.conf\ndeny = 5\n\n@@end\n")


def _bdu_xlsx(path) -> None:
    """Мини-выгрузка БДУ в раскладке vullist.xlsx: две строки шапки + заголовок."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Описание уязвимостей"])
    ws.append(["Общая информация"])
    ws.append(HEADER)
    row = [None] * len(HEADER)
    row[0], row[1] = "BDU:2024-04970", "Уязвимость OpenSSH (regreSSHion)"
    row[13] = "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 8,1)"
    row[14] = "Обновить OpenSSH"
    row[19] = "CVE-2024-6387"
    ws.append(row)
    wb.save(path)


class _SetAuth:
    """Проверка входа без сети: подходит только одна пара из набора."""

    def __init__(self):
        self.tried: list[tuple[str, str]] = []

    def authenticate(self, host, port, service, credential, timeout):
        self.tried.append((credential.username, credential.secret))
        ok = (credential.username, credential.secret) == ("admin", SET_SECRET)
        return AuthResult(AuthOutcome.SUCCESS if ok else AuthOutcome.FAILURE)


@pytest.fixture
def world(sqlite_factory, tmp_path, monkeypatch):
    engine = sqlite_factory.kw["bind"]
    store = SqlReferenceStore(engine)
    store.create_schema()
    # NVD грузится по сети — кладём запись напрямую; БДУ — через планировщик R12.
    store.upsert_nvd([parse_cve_item(nvd_item("CVE-2024-6387", 8.1, [{
        "vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}]))])
    xlsx = tmp_path / "vullist.xlsx"
    _bdu_xlsx(xlsx)
    monkeypatch.setattr(core_settings, "bdu_fstec_feed_path", str(xlsx))
    monkeypatch.setattr(core_settings, "bdu_fstec_feed_url", "")

    scap = tmp_path / "ssg"
    scap.mkdir()
    (scap / "ssg-debian12-ds.xml").write_bytes(DS)
    lynis = tmp_path / "lynis.tar.gz"
    lynis.write_bytes(b"lynis-bundle")
    net = FakeNet(policy={HOST: POLICY})
    auth = _SetAuth()
    rec = Recorder()
    matcher = VulnMatcher(store)
    registry = {
        "discovery": lambda: FakeDiscovery(rec),
        "auth_inventory": lambda: AuthInventoryModule(
            matcher=matcher, connector=lambda h, c, o: DpkgShell(DPKG_OUT),
            sleep=lambda s: None),
        # win_inventory входит в движок «По учётной записи»; без WinRM-учётки
        # инертен — в этом прогоне учётка SSH.
        "win_inventory": _InertModule,
        "config_audit": lambda: ConfigAuditModule(
            ConfigAuditOptions(scap_dir=str(scap), lynis_bundle=str(lynis)),
            connector=net, sleep=lambda s: None),
        "password_policy": PasswordPolicyModule,
        "cred_audit": lambda: CredentialAuditModule(authenticator=auth,
                                                    sleep=lambda s: None),
    }
    app = create_app(
        session_factory=sqlite_factory,
        settings=ApiSettings(secret=SECRET, bootstrap_admin="root",
                             bootstrap_password=PASSWORD, feeds_tick_seconds=0),
        registry=registry, executor=inline_executor(),
        feed_sources={"bdu": FeedSource("bdu", "БДУ ФСТЭК", load_bdu)},
        feed_executor=inline_executor(),
        resolver_factory=lambda findings: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c), net, auth


def _audit_rows(sqlite_factory):
    with sqlite_factory() as s:
        return [tuple(r) for r in s.execute(
            select(AuditLogRow.action, AuditLogRow.target, AuditLogRow.result,
                   AuditLogRow.details).order_by(AuditLogRow.id))]


def _prepare(api: Api):
    """Договор, учётка, набор проверки, актив в группе; справочник БДУ через R12."""
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator", "host_credentials", "cred_audit")
    r = api.c.post("/feeds/bdu/run", headers=api.admin)
    assert r.status_code == 202, r.text
    feed = next(f for f in api.c.get("/feeds", headers=op).json() if f["source"] == "bdu")
    assert (feed["last_result"], feed["last_count"]) == ("ok", 1), feed

    r = api.c.post(f"/engagements/{eid}/credentials", headers=op,
                   json={"name": "аудит", "username": "auditor", "auth": "password",
                         "password": HOST_PASSWORD, "become": "sudo"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    r = api.c.post(f"/engagements/{eid}/cred-sets", headers=op,
                   json={"name": "стандартные", "services": ["ssh"],
                         "entries": [{"username": "root", "secret": "toor"},
                                     {"username": "admin", "secret": SET_SECRET}]})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    g = api.c.post(f"/engagements/{eid}/asset-groups", headers=api.admin,
                   json={"name": "DMZ"}).json()
    r = api.c.post(f"/engagements/{eid}/assets", headers=api.admin,
                   json={"address": HOST, "criticality": "high", "group_ids": [g["id"]]})
    assert r.status_code == 201, r.text
    return eid, op, cid, sid, g["id"]


def test_wave1_run_end_to_end(world, sqlite_factory):
    api, net, auth = world
    eid, op, cid, sid, gid = _prepare(api)

    r = api.c.post(f"/engagements/{eid}/runs", headers=op, json={
        "targets": [HOST], "modules": ["discovery", "config_audit", "cred_audit"],
        "vuln_engine": "credentialed", "credential_ids": [cid], "cred_set_ids": [sid]})
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["status"] == "done", run
    # password_policy поставлен автоматически вместе с config_audit, в имени его нет
    assert run["modules"] == ["discovery", "auth_inventory", "win_inventory",
                              "config_audit", "password_policy", "cred_audit"]
    assert "password_policy" not in run["name"]

    findings = api.c.get(f"/runs/{run['id']}/findings", headers=op).json()
    by_id = {f["vuln_id"]: f for f in findings}
    # auth_inventory: пакет -> CVE -> БДУ, загруженная планировщиком справочников
    ssh = by_id["CVE-2024-6387"]
    assert ssh["module"] == "auth_inventory" and "BDU:2024-04970" in ssh["bdu_ids"]
    # config_audit по учётке: нарушения бенчмарка, а не «нет учётной записи»
    assert by_id[RULE + "sshd_disable_root_login"]["module"] == "config_audit"
    assert "INFO:config-audit-no-credentials" not in by_id
    assert "прочитано файлов — 2" in by_id["INFO:config-audit"]["evidence"]
    # password_policy оценил конфигурацию, собранную config_audit
    policy = {k for k, f in by_id.items() if f["module"] == "password_policy"}
    assert policy == {"POLICY:password-min-length", "POLICY:password-complexity",
                      "POLICY:password-max-age"}            # блокировка настроена
    # cred_audit: слабая пара из набора найдена
    assert by_id["CRED:ssh/admin"]["severity"] == "critical"
    assert ("admin", SET_SECRET) in auth.tried

    # файлы политики читались без sudo и без stdin
    policy_calls = [(c, s) for _, _, c, s in net.calls if "@@scanner-policy-file" in c]
    assert policy_calls and all(not c.startswith("sudo") and s is None
                                for c, s in policy_calls)

    audit = _audit_rows(sqlite_factory)
    results = {(a, res) for a, _, res, _ in audit}
    assert ("config_audit_skip", "no_credentials") not in results
    assert ("password_policy_skip", "no_policy_data") not in results
    assert ("config_audit_policy", "ok") in results
    assert ("password_policy_eval", "ok") in results
    assert not any(a == "cred_audit_skip" for a, _, _, _ in audit)

    # отчёт по группе активов R7: находки всех модулей волны 1
    rep = api.c.get(f"/runs/{run['id']}/report?format=json&group_id={gid}", headers=op)
    assert rep.status_code == 200, rep.text
    data = json.loads(rep.text)
    assert data["meta"]["group"] == "DMZ"
    modules = {f["module"] for f in data["combined"]["findings"]}
    assert {"auth_inventory", "config_audit", "password_policy",
            "cred_audit"} <= modules
    html = api.c.get(f"/runs/{run['id']}/report?format=html&group_id={gid}",
                     headers=op).text
    assert "Парольная политика" in html and "BDU:2024-04970" in html

    # секреты — нигде снаружи
    blob = json.dumps(audit, default=str, ensure_ascii=False) + rep.text + html \
        + json.dumps(findings, ensure_ascii=False) + r.text
    assert HOST_PASSWORD not in blob and SET_SECRET not in blob


def test_password_policy_inert_without_config_audit(world, sqlite_factory):
    """Без config_audit конфигурацию никто не собрал: password_policy, заданный
    явно, только пишет осознанный пропуск."""
    api, net, _ = world
    eid, op, *_ = _prepare(api)
    r = api.c.post(f"/engagements/{eid}/runs", headers=op, json={
        "targets": [HOST], "modules": ["discovery", "password_policy"]})
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["status"] == "done" and run["modules"] == ["discovery", "password_policy"]
    findings = api.c.get(f"/runs/{run['id']}/findings", headers=op).json()
    assert not any(f["module"] == "password_policy" for f in findings)
    assert ("password_policy_skip", "no_policy_data") in {
        (a, res) for a, _, res, _ in _audit_rows(sqlite_factory)}
    assert not net.connects                              # ни одного входа на хост


def test_with_companions_respects_registry():
    from scanner.core.orchestrator import with_companions
    assert with_companions(["discovery", "config_audit"]) == [
        "discovery", "config_audit", "password_policy"]
    assert with_companions(["config_audit"], known={"config_audit"}) == ["config_audit"]
    assert with_companions(["config_audit", "password_policy"]) == [
        "config_audit", "password_policy"]
