"""Распределённые сканеры: узлы, задания, результат, allowlist в центре и на узле."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core import coverage as cv
from scanner.core.credentials import HostCredential
from scanner.core.db import AuditLogRow, FindingRow, ScanRun
from scanner.core.models import (
    Finding,
    FindingType,
    HostInventory,
    HostOs,
    InstalledPackage,
    ServiceInfo,
    Severity,
)
from scanner.core.orchestrator import RunOutcome, inline_executor
from scanner.modules.base import ScanContext, ScanModule
from scanner.nodes import store as nodes
from scanner.nodes.agent import BufferedAudit, NodeAgent, NodeConfig, execute_job
from scanner.nodes.codec import (
    CodecError,
    NodeJob,
    decode_job,
    decode_outcome,
    encode_job,
    encode_outcome,
    from_wire,
    to_wire,
)
from scanner.nodes.remote import NodeApiError, NodeClient, RemoteReferenceStore
from tests.test_api import Api, Recorder, _make


# ---------- фиктивные модули узла ----------
class NodeDiscovery(ScanModule):
    name = "discovery"

    def __init__(self, rec: Recorder, rogue: str | None = None):
        self.rec, self.rogue = rec, rogue

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.rec.seen.setdefault("node_targets", []).extend(ctx.targets)
        ctx.services = [ServiceInfo(t, 22, "tcp", "ssh", "OpenSSH", "7.4") for t in ctx.targets]
        ctx.hosts = {t: HostOs(t, "Linux", "linux", 95, "nmap") for t in ctx.targets}
        out = [Finding(module=self.name, host=t, finding_type=FindingType.VULN,
                       title="CVE-2016-6210 in OpenSSH", severity=Severity.HIGH, port=22,
                       vuln_id="CVE-2016-6210", cve_ids=["CVE-2016-6210"])
               for t in ctx.targets]
        if self.rogue:   # скомпрометированный узел «дописывает» чужой хост
            out.append(Finding(module=self.name, host=self.rogue,
                               finding_type=FindingType.VULN, title="fake",
                               severity=Severity.CRITICAL, vuln_id="CVE-2000-0001"))
        return out


class StopAware(ScanModule):
    name = "vuln"

    def __init__(self, flag: dict):
        self.flag = flag

    def run(self, ctx: ScanContext) -> list[Finding]:
        self.flag["ran"] = True
        return []


# ---------- кодек ----------
def test_codec_roundtrip_job_with_credentials():
    cred = HostCredential(id=3, name="root", auth="password", username="root",
                          targets=("10.1.0.0/24",), password="s3cr3t",
                          options={"platform": "linux"})
    job = NodeJob(scan_run_id=7, engagement_id=1, modules=["discovery"],
                  rate_profile="gentle", targets=["10.1.0.5"], allowlist=["10.1.0.0/24"],
                  options={"no_ping": True}, credentials=[cred],
                  cred_candidates=[("admin", "admin")], progress_history={"discovery": 1.5})
    back = decode_job(encode_job(job))
    assert back.credentials[0].password == "s3cr3t"
    assert back.credentials[0].targets == ("10.1.0.0/24",)
    assert back.cred_candidates == [("admin", "admin")]
    assert back.options == {"no_ping": True}


def test_codec_roundtrip_outcome():
    out = RunOutcome(allowed=["10.1.0.5"])
    out.findings = [Finding(module="vuln", host="10.1.0.5", finding_type=FindingType.VULN,
                            title="x", severity=Severity.HIGH, vuln_id="CVE-1",
                            cve_ids=["CVE-1"], bdu_ids=["BDU:2020-1"])]
    out.inventory = [HostInventory(host="10.1.0.5", os_id="debian", packages=[
        InstalledPackage(name="openssl", version="3.0.1", manager="dpkg")])]
    out.coverage.mark("10.1.0.5", "vuln", cv.COMPLETED)
    out.compliance_facts = {"10.1.0.5": {"checks": {"a", "b"}}}
    rid, back = decode_outcome(encode_outcome(out, scan_run_id=9))
    assert rid == 9
    assert back.findings[0].severity is Severity.HIGH
    assert back.inventory[0].packages[0].name == "openssl"
    assert back.coverage.status("10.1.0.5", "vuln") == cv.COMPLETED
    assert back.compliance_facts["10.1.0.5"]["checks"] == {"a", "b"}


@pytest.mark.parametrize("ref", ["os:system", "subprocess:Popen", "builtins:object",
                                 "scanner.core.db:Base.metadata"])
def test_codec_rejects_foreign_classes(ref):
    with pytest.raises(CodecError):
        from_wire({"$dc": ref, "f": {}})


def test_codec_rejects_other_format():
    data = encode_job(NodeJob(1, 1, ["discovery"], "gentle", [], []))
    data["format"] = 99
    with pytest.raises(CodecError, match="формат"):
        decode_job(data)
    assert to_wire({1: "a"}) == {"$map": [[1, "a"]]}


# ---------- узлы в БД ----------
def test_node_tokens_and_scope(sqlite_factory):
    with sqlite_factory() as s:
        node, token = nodes.create_node(s, name="Филиал-1", scope=["10.1.0.0/24",
                                                                   "10.2.0.1-10.2.0.9"])
        s.commit()
        assert token and token.startswith(nodes.TOKEN_PREFIX)
        assert node.token_hash == nodes.hash_token(token) and token not in node.token_hash
        assert nodes.authenticate(s, token).id == node.id
        assert nodes.authenticate(s, token + "x") is None
        new = nodes.rotate_token(s, node)
        assert nodes.authenticate(s, token) is None
        assert nodes.authenticate(s, new).id == node.id
        node.enabled = False
        assert nodes.authenticate(s, new) is None
        off, t2 = nodes.create_node(s, name="АСУ ТП", scope=["192.168.5.0/24"],
                                    mode=nodes.MODE_OFFLINE)
        assert t2 is None and nodes.node_status(off) == nodes.STATUS_AUTONOMOUS
        with pytest.raises(nodes.NodeError):
            nodes.create_node(s, name="Пусто", scope=[])
        with pytest.raises(nodes.NodeError):
            nodes.create_node(s, name="Филиал-1", scope=["10.9.0.0/24"])


def test_intersect_networks():
    assert nodes.intersect_networks(["10.0.0.0/8"], ["10.1.0.0/24"]) == ["10.1.0.0/24"]
    assert nodes.intersect_networks(["10.1.0.5/32"], ["10.1.0.0/24"]) == ["10.1.0.5/32"]
    assert nodes.intersect_networks(["10.1.0.0/24"], ["10.2.0.0/24"]) == []


# ---------- узел: локальный allowlist ----------
def test_execute_job_enforces_local_allowlist():
    rec = Recorder()
    job = NodeJob(scan_run_id=1, engagement_id=1, modules=["discovery"],
                  rate_profile="gentle", targets=["10.1.0.5", "10.1.0.200"],
                  allowlist=["10.1.0.0/24"])
    audit = BufferedAudit(lambda recs: None)
    out = execute_job(job, {"discovery": lambda: NodeDiscovery(rec)}, audit=audit,
                      local_allowlist=["10.1.0.0/25"])
    # 10.1.0.200 вне локального allowlist узла — не тронут, отказ в аудите
    assert rec.seen["node_targets"] == ["10.1.0.5"]
    assert out.allowed == ["10.1.0.5"]
    assert any(r["action"] == "deny" for r in audit._buf)


def test_execute_job_unknown_module():
    job = NodeJob(1, 1, ["netdev_audit"], "gentle", ["10.1.0.5"], ["10.1.0.0/24"])
    with pytest.raises(ValueError, match="обновите образ узла"):
        execute_job(job, {}, audit=BufferedAudit(lambda r: None),
                    local_allowlist=["10.1.0.0/24"])


# ---------- сквозной сценарий через API ----------
@pytest.fixture
def stack(sqlite_factory):
    rec = Recorder()
    app = _make(sqlite_factory, rec, ["CVE-2016-6210"], inline_executor())
    with TestClient(app) as c:
        api = Api(c)
        yield api, rec, app


def _node_client(c: TestClient, token: str) -> NodeClient:
    class _Bridge(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            r = c.request(request.method, request.url.path, content=request.read(),
                          headers=dict(request.headers))
            return httpx.Response(r.status_code, content=r.content, headers=r.headers)

    return NodeClient("http://central", token, transport=_Bridge(), prefix="/node/v1")


def _create_node(api: Api, **kw) -> dict:
    body = {"name": "Филиал-1", "scope": ["10.1.0.0/24"], **kw}
    r = api.c.post("/nodes", headers=api.admin, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_node_run_end_to_end(stack, sqlite_factory):
    api, rec, _app = stack
    eid = api.engagement("10.0.0.0/8")
    op = api.user("op", "operator")
    node = _create_node(api)
    assert node["token"] and node["status"] == nodes.STATUS_NEVER

    # оператор видит узлы, но не заводит их
    assert api.c.get("/nodes", headers=op).status_code == 200
    assert "token" not in api.c.get("/nodes", headers=op).json()[0]
    assert api.c.post("/nodes", headers=op, json={"name": "x", "scope": ["10.5.0.0/24"]}
                      ).status_code == 403

    r = api.c.post(f"/engagements/{eid}/runs", headers=op,
                   json={"targets": ["10.1.0.5", "10.1.0.6", "10.3.0.1"],
                         "modules": ["discovery"], "node_id": node["id"]})
    assert r.status_code == 202, r.text
    run_id = r.json()["id"]
    assert r.json()["node_id"] == node["id"]
    # центр не исполняет прогон узла сам
    assert r.json()["status"] == "pending" and "discovery" not in rec.seen

    client = _node_client(api.c, node["token"])
    cfg = NodeConfig(server="http://central", token=node["token"],
                     allowlist=["10.1.0.0/24"], spool=None, heartbeat_seconds=0.05)
    agent = NodeAgent(client, cfg, registry={"discovery": lambda: NodeDiscovery(rec)})
    hello = agent.hello()
    assert hello["node"]["name"] == "Филиал-1"
    assert agent.run_once() is True
    # 10.3.0.1 вне сетей узла — центр его не выдал
    assert rec.seen["node_targets"] == ["10.1.0.5", "10.1.0.6"]

    run = api.c.get(f"/runs/{run_id}", headers=op).json()
    assert run["status"] == "done", run
    with sqlite_factory() as s:
        hosts = {str(f.host) for f in s.scalars(select(FindingRow)
                                               .where(FindingRow.scan_run_id == run_id))}
        assert hosts == {"10.1.0.5", "10.1.0.6"}
        acts = {(a.subject, a.action) for a in s.scalars(select(AuditLogRow))}
    assert ("node:Филиал-1", "node_register") in acts
    assert ("node:Филиал-1", "module_start") in acts          # аудит действий узла
    assert ("scanner", "node_job") in acts

    listed = api.c.get(f"/nodes/{node['id']}", headers=op).json()
    assert listed["status"] == nodes.STATUS_ONLINE
    assert listed["local_allowlist"] == ["10.1.0.0/24"]
    assert agent.run_once() is False          # заданий больше нет


def test_node_result_cannot_inject_foreign_hosts(stack, sqlite_factory):
    api, rec, _app = stack
    eid = api.engagement("10.0.0.0/8", "172.16.0.0/12")
    node = _create_node(api)
    r = api.c.post(f"/engagements/{eid}/runs", headers=api.user("op", "operator"),
                   json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                         "node_id": node["id"]})
    run_id = r.json()["id"]
    client = _node_client(api.c, node["token"])
    cfg = NodeConfig("http://central", node["token"], ["10.1.0.0/24"], spool=None,
                     heartbeat_seconds=0.05)
    # 172.16.0.9 в allowlist договора, но не в сетях узла
    agent = NodeAgent(client, cfg,
                      registry={"discovery": lambda: NodeDiscovery(rec, rogue="172.16.0.9")})
    agent.run_once()
    with sqlite_factory() as s:
        hosts = {str(f.host) for f in s.scalars(select(FindingRow)
                                               .where(FindingRow.scan_run_id == run_id))}
        acts = [a.action for a in s.scalars(select(AuditLogRow))]
    assert hosts == {"10.1.0.5"}
    assert "node_result_filtered" in acts


def test_node_auth_is_separate_from_users(stack):
    api, _rec, _app = stack
    node = _create_node(api)
    # токен пользователя не работает в протоколе узла
    assert api.c.post("/node/v1/jobs/next", headers=api.admin).status_code == 401
    # токен узла не работает в API людей
    hdr = {"Authorization": f"Bearer {node['token']}"}
    assert api.c.get("/nodes", headers=hdr).status_code == 401
    assert api.c.post("/node/v1/jobs/next", headers=hdr).json() == {"job": None}
    # перевыпуск: старый токен перестаёт действовать
    new = api.c.post(f"/nodes/{node['id']}/token", headers=api.admin).json()["token"]
    assert api.c.post("/node/v1/jobs/next", headers=hdr).status_code == 401
    assert api.c.post("/node/v1/jobs/next",
                      headers={"Authorization": f"Bearer {new}"}).status_code == 200
    # отключённый узел не подключается
    api.c.patch(f"/nodes/{node['id']}", headers=api.admin, json={"enabled": False})
    assert api.c.post("/node/v1/jobs/next",
                      headers={"Authorization": f"Bearer {new}"}).status_code == 401


def test_node_credentials_policy(stack):
    api, _rec, _app = stack
    node = _create_node(api, allow_credentials=False)
    eid = api.engagement("10.0.0.0/8")
    r = api.c.post(f"/engagements/{eid}/runs", headers=api.user("op", "operator"),
                   json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                         "node_id": node["id"], "credential_ids": [1]})
    assert r.status_code in (403, 422)


def test_node_stop_and_heartbeat(stack):
    api, _rec, _app = stack
    eid = api.engagement("10.0.0.0/8")
    op = api.user("op", "operator")
    node = _create_node(api)
    run_id = api.c.post(f"/engagements/{eid}/runs", headers=op,
                        json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                              "node_id": node["id"]}).json()["id"]
    hdr = {"Authorization": f"Bearer {node['token']}"}
    job = api.c.post("/node/v1/jobs/next", headers=hdr).json()["job"]
    assert job["kind"] == "scanner-node-job"
    hb = api.c.post(f"/node/v1/jobs/{run_id}/heartbeat", headers=hdr,
                    json={"progress": {"percent": 10}}).json()
    assert hb == {"status": "running", "stop": False}
    assert api.c.get(f"/runs/{run_id}", headers=op).json()["progress"] == {"percent": 10}
    api.c.post(f"/runs/{run_id}/stop", headers=op)
    hb = api.c.post(f"/node/v1/jobs/{run_id}/heartbeat", headers=hdr, json={}).json()
    assert hb["stop"] is True
    # чужой прогон узлу недоступен
    other = _create_node(api, name="Филиал-2", scope=["10.2.0.0/24"])
    hdr2 = {"Authorization": f"Bearer {other['token']}"}
    assert api.c.post(f"/node/v1/jobs/{run_id}/heartbeat", headers=hdr2,
                      json={}).status_code == 404


def test_node_fail_marks_run_failed(stack):
    api, _rec, _app = stack
    eid = api.engagement("10.0.0.0/8")
    node = _create_node(api)
    op = api.user("op", "operator")
    run_id = api.c.post(f"/engagements/{eid}/runs", headers=op,
                        json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                              "node_id": node["id"]}).json()["id"]
    client = _node_client(api.c, node["token"])
    agent = NodeAgent(client, NodeConfig("http://c", node["token"], ["10.1.0.0/24"],
                                         spool=None, heartbeat_seconds=0.05), registry={})
    agent.run_once()     # модуля discovery на «старом» узле нет
    run = api.c.get(f"/runs/{run_id}", headers=op).json()
    assert run["status"] == "failed" and "обновите образ узла" in run["error_message"]


def test_recovery_leaves_node_runs_alone(stack, sqlite_factory):
    api, _rec, app = stack
    eid = api.engagement("10.0.0.0/8")
    online = _create_node(api)
    op = api.user("op", "operator")
    r1 = api.c.post(f"/engagements/{eid}/runs", headers=op,
                    json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                          "node_id": online["id"]}).json()["id"]
    r2 = api.c.post(f"/engagements/{eid}/runs", headers=op,
                    json={"targets": ["10.1.0.6"], "modules": ["discovery"],
                          "node_id": online["id"]}).json()["id"]
    hdr = {"Authorization": f"Bearer {online['token']}"}
    api.c.post("/node/v1/jobs/next", headers=hdr)        # r1 -> running на узле
    with sqlite_factory() as s:
        off, _ = nodes.create_node(s, name="АСУ ТП", scope=["192.168.5.0/24"],
                                   mode=nodes.MODE_OFFLINE)
        s.flush()
        r3 = ScanRun(engagement_id=eid, modules=["discovery"], status="running",
                     node_id=off.id, heartbeat_at=datetime.now(UTC) - timedelta(days=3),
                     started_at=datetime.now(UTC) - timedelta(days=3))
        s.add(r3)
        s.commit()
        r3 = r3.id
    runs = app.state.runs
    res = runs.recover_orphans(now=datetime.now(UTC) + timedelta(hours=1))
    assert res["requeued"] == []                  # pending узла не уходит в локальную очередь
    assert res["interrupted"] == [r1]             # узел замолчал во время прогона
    with sqlite_factory() as s:
        st = {r.id: (r.status, r.error_message) for r in s.scalars(select(ScanRun))}
    assert st[r2][0] == "pending"
    assert st[r3][0] == "running"                 # автономный: ждёт носитель
    assert "узел-сканер" in st[r1][1]


def test_reference_rpc_whitelist(stack, sqlite_factory):
    api, _rec, _app = stack
    node = _create_node(api)
    hdr = {"Authorization": f"Bearer {node['token']}"}
    from scanner.feeds.store import SqlReferenceStore
    SqlReferenceStore(sqlite_factory.kw["bind"]).create_schema()
    r = api.c.post("/node/v1/reference", headers=hdr,
                   json={"store": "reference", "method": "get_nvd", "args": ["CVE-1-1"]})
    assert r.status_code == 200 and r.json() == {"result": None}
    for bad in ({"store": "reference", "method": "upsert_bdu", "args": [[]]},
                {"store": "reference", "method": "__init__", "args": []},
                {"store": "reference", "method": "get_nvd", "args": [{"x": 1}]}):
        assert api.c.post("/node/v1/reference", headers=hdr, json=bad).status_code == 422
    client = _node_client(api.c, node["token"])
    store = RemoteReferenceStore(client)
    assert store.bdu_by_cve("CVE-2016-6210") == []
    with pytest.raises(RuntimeError):
        store.upsert_bdu([])


def test_node_api_error_on_bad_token(stack):
    api, _rec, _app = stack
    client = _node_client(api.c, "snode_wrong")
    with pytest.raises(NodeApiError) as e:
        client.next_job()
    assert e.value.status == 401


def test_client_requires_https():
    with pytest.raises(ValueError, match="HTTPS"):
        NodeClient("http://scanner.example", "snode_x")
    NodeClient("https://scanner.example", "snode_x").close()


def test_admin_deletes_node_without_active_runs(stack):
    api, _rec, _app = stack
    node = _create_node(api)
    eid = api.engagement("10.0.0.0/8")
    r = api.c.post(f"/engagements/{eid}/runs", headers=api.user("op", "operator"),
                   json={"targets": ["10.1.0.5"], "modules": ["discovery"],
                         "node_id": node["id"]})
    assert r.status_code == 202
    assert api.c.delete(f"/nodes/{node['id']}", headers=api.admin).status_code == 409


# ---------- PostgreSQL (схема из миграций, JSONB/INET) ----------
from tests.conftest import PG_URL
from tests.test_migrations_pg import pg_factory  # noqa: F401 — фикстура


@pytest.mark.skipif(not PG_URL, reason="SCANNER_TEST_DATABASE_URL not set")
def test_node_run_on_postgres(pg_factory):  # noqa: F811
    rec = Recorder()
    app = _make(pg_factory, rec, [], inline_executor())
    with TestClient(app) as c:
        api = Api(c)
        eid = api.engagement("10.0.0.0/8")
        op = api.user("op", "operator")
        node = _create_node(api)
        run_id = c.post(f"/engagements/{eid}/runs", headers=op,
                        json={"targets": ["10.1.0.0/30"], "modules": ["discovery"],
                              "node_id": node["id"]}).json()["id"]
        agent = NodeAgent(_node_client(c, node["token"]),
                          NodeConfig("http://c", node["token"], ["10.1.0.0/24"], spool=None,
                                     heartbeat_seconds=0.05),
                          registry={"discovery": lambda: NodeDiscovery(rec)})
        agent.hello()
        assert agent.run_once()
        run = c.get(f"/runs/{run_id}", headers=op).json()
        assert run["status"] == "done" and run["node_id"] == node["id"]
        assert c.get("/nodes", headers=op).json()[0]["status"] == nodes.STATUS_ONLINE


def test_mtls_pins_certificate(stack, monkeypatch):
    api, _rec, _app = stack
    node = _create_node(api)
    monkeypatch.setenv("SCANNER_NODE_MTLS_VERIFY_HEADER", "X-SSL-Client-Verify")
    monkeypatch.setenv("SCANNER_NODE_MTLS_FINGERPRINT_HEADER", "X-SSL-Client-Fingerprint")
    hdr = {"Authorization": f"Bearer {node['token']}"}
    assert api.c.post("/node/v1/jobs/next", headers=hdr).status_code == 401
    ok = {**hdr, "X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-Fingerprint": "AA11"}
    assert api.c.post("/node/v1/jobs/next", headers=ok).status_code == 200
    other = {**ok, "X-SSL-Client-Fingerprint": "BB22"}
    assert api.c.post("/node/v1/jobs/next", headers=other).status_code == 401
    # перевыпуск токена сбрасывает закреплённый сертификат
    new = api.c.post(f"/nodes/{node['id']}/token", headers=api.admin).json()["token"]
    other["Authorization"] = f"Bearer {new}"
    assert api.c.post("/node/v1/jobs/next", headers=other).status_code == 200


def test_templates_archive_roundtrip(tmp_path):
    import tarfile

    from scanner.nodes.templates import build_archive, fingerprint, install_archive
    src = tmp_path / "src"
    (src / "http" / "cves").mkdir(parents=True)
    (src / "http" / "cves" / "a.yaml").write_text("id: a\n")
    (src / "b.yaml").write_text("id: b\n")
    archive, etag = build_archive(src, tmp_path / "cache")
    assert etag == fingerprint(src)
    assert build_archive(src, tmp_path / "cache") == (archive, etag)   # из кэша
    target = tmp_path / "dst" / "nuclei-templates"
    target.mkdir(parents=True)
    (target / "old.yaml").write_text("old")
    assert install_archive(archive, target) == 2
    assert (target / "http" / "cves" / "a.yaml").read_text() == "id: a\n"
    assert not (target / "old.yaml").exists()
    # выход за каталог и ссылки отбрасываются
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        p = tmp_path / "x.yaml"
        p.write_text("x")
        tar.add(p, arcname="../../escape.yaml")
        info = tarfile.TarInfo("link.yaml")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
        tar.add(p, arcname="ok.yaml")
    assert install_archive(evil, target) == 1
    assert not (tmp_path / "escape.yaml").exists() and not (target / "link.yaml").exists()


def test_node_config_requires_local_allowlist():
    from scanner.nodes.agent import NodeConfigError, config_from_env
    with pytest.raises(NodeConfigError, match="SCANNER_NODE_ALLOWLIST"):
        config_from_env({"SCANNER_NODE_SERVER": "https://c", "SCANNER_NODE_TOKEN": "t"})
    cfg = config_from_env({"SCANNER_NODE_SERVER": "https://c", "SCANNER_NODE_TOKEN": "t",
                           "SCANNER_NODE_ALLOWLIST": "10.1.0.0/24, 10.2.0.1-10.2.0.5"})
    assert cfg.allowlist == ["10.1.0.0/24", "10.2.0.1-10.2.0.5"]
