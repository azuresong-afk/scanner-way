"""Автономный режим целиком: центр -> файл задания -> узел -> файл результата -> центр."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core.db import AuditLogRow, FindingRow, OfflineJobRow, ScanRun
from scanner.core.orchestrator import RunService, inline_executor
from scanner.nodes import offline_center as oc
from scanner.nodes import offline_files as of
from scanner.nodes import offline_node as on
from scanner.nodes.offline_crypto import ROLE_NODE, KeyPair
from tests.test_api import Api, Recorder, _make
from tests.test_nodes import NodeDiscovery


@pytest.fixture
def stack(sqlite_factory):
    rec = Recorder()
    app = _make(sqlite_factory, rec, ["CVE-2016-6210"], inline_executor())
    with TestClient(app) as c:
        api = Api(c)
        api.op = api.user("op", "operator")     # прогоны, выгрузка, загрузка
        yield api, rec, app


def _center_pub(api: Api):
    r = api.c.get("/offline/center-key?format=file", headers=api.admin)
    assert r.status_code == 200, r.text
    assert "center.pub" in r.headers["content-disposition"]
    return r.text


@pytest.fixture
def offline(stack, tmp_path):
    """Автономный узел «АСУ-ТП-1»: заведён в центре, установлен, ключ загружен."""
    api, rec, app = stack
    eid = api.engagement("10.0.0.0/8", "172.16.0.0/12")
    r = api.c.post("/nodes", headers=api.admin,
                   json={"name": "АСУ-ТП-1", "scope": ["10.1.0.0/24"], "mode": "offline"})
    assert r.status_code == 201, r.text
    node_id = r.json()["id"]
    assert r.json().get("token") is None
    on.init_node(tmp_path / "node", name="АСУ-ТП-1", scope=["10.1.0.0/24"],
                 center_key=_center_pub(api))
    node = on.OfflineNode.load(tmp_path / "node")
    r = api.c.put(f"/nodes/{node_id}/public-key", headers=api.admin,
                  json={"public_key": (tmp_path / "node" / on.NODE_PUB_FILE).read_text()})
    assert r.status_code == 200, r.text
    assert r.json()["fingerprint"] == node.public.fingerprint
    return api, rec, app, eid, node_id, node


def _start(api: Api, eid: int, node_id: int, targets=("10.1.0.5",)) -> int:
    r = api.c.post(f"/engagements/{eid}/runs", headers=api.op,
                   json={"targets": list(targets), "modules": ["discovery"],
                         "node_id": node_id})
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "pending"
    return r.json()["id"]


def _export(api: Api, run_id: int, **params) -> bytes:
    r = api.c.post(f"/runs/{run_id}/offline/export", headers=api.op, params=params)
    assert r.status_code == 200, r.text
    assert ".scnjob" in r.headers["content-disposition"]
    return r.content


def _run_on_node(node, data: bytes, rec, rogue=None, **kw) -> bytes:
    result, header = on.run_job(node, data,
                                registry={"discovery": lambda: NodeDiscovery(rec, rogue=rogue)},
                                **kw)
    on.record_done(node, header, "result.scnres")
    return result


def _import(api: Api, data: bytes, expect: int = 200) -> dict:
    r = api.c.post("/offline/results", headers={**api.op,
                                               "Content-Type": "application/octet-stream"},
                   content=data)
    assert r.status_code == expect, r.text
    return r.json()


def test_offline_run_end_to_end(offline, sqlite_factory):
    api, rec, _app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id)
    job = _export(api, run_id)
    # прогон за узлом, задание ждёт результат; цели в файле не видны
    assert api.c.get(f"/runs/{run_id}", headers=api.op).json()["status"] == "running"
    assert b"10.1.0.5" not in job
    status = api.c.get(f"/runs/{run_id}/offline", headers=api.op).json()
    assert status["status"] == "exported" and status["node_name"] == "АСУ-ТП-1"
    # центр не исполнял прогон сам
    assert "node_targets" not in rec.seen

    result = _run_on_node(node, job, rec)
    assert rec.seen["node_targets"] == ["10.1.0.5"]
    head = api.c.post("/offline/results/preview", headers=api.op, content=result).json()
    assert head["run_id"] == run_id and head["findings"] == 1

    out = _import(api, result)
    assert out["run_id"] == run_id and out["status"] == "done" and out["findings"] == 1
    run = api.c.get(f"/runs/{run_id}", headers=api.op).json()
    assert run["status"] == "done"
    with sqlite_factory() as s:
        hosts = {str(f.host) for f in s.scalars(select(FindingRow).where(
            FindingRow.scan_run_id == run_id))}
        acts = [(a.subject, a.action) for a in s.scalars(select(AuditLogRow))]
    assert hosts == {"10.1.0.5"}
    assert ("user:op", "offline_job_export") in acts
    assert ("user:op", "offline_result_import") in acts
    # журнал узла перенесён в журнал центра
    assert ("node:АСУ-ТП-1", "offline_job_start") in acts
    assert ("node:АСУ-ТП-1", "module_start") in acts
    jobs = api.c.get(f"/nodes/{node_id}/offline-jobs", headers=api.admin).json()
    assert [j["status"] for j in jobs] == ["imported"]

    # повторная загрузка того же результата
    r = api.c.post("/offline/results", headers=api.op, content=result)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "already_imported"


def test_center_only_runs_nodes_scope_and_filters_foreign_hosts(offline, sqlite_factory):
    api, rec, _app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id, targets=("10.1.0.5", "172.16.0.9"))
    result = _run_on_node(node, _export(api, run_id), rec, rogue="172.16.0.9")
    # 172.16.0.9 в договоре, но вне сетей узла: в задание не попал, а
    # «дописанная» узлом находка отброшена при загрузке
    assert rec.seen["node_targets"] == ["10.1.0.5"]
    out = _import(api, result)
    assert out["dropped"]["findings"] == 1
    with sqlite_factory() as s:
        hosts = {str(f.host) for f in s.scalars(select(FindingRow).where(
            FindingRow.scan_run_id == run_id))}
    assert hosts == {"10.1.0.5"}


def test_tampered_and_foreign_results_rejected(offline, tmp_path):
    api, rec, _app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id)
    job = _export(api, run_id)
    result = _run_on_node(node, job, rec)

    doc = json.loads(result)
    doc["header"]["findings"] = 0
    r = api.c.post("/offline/results", headers=api.op, content=json.dumps(doc).encode())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "bad_signature"

    # результат, подписанный посторонним ключом под видом узла
    evil = KeyPair.generate(ROLE_NODE)
    env = of.parse(result, of.FORMAT_RESULT)
    hdr = {k: v for k, v in env.header.items() if k not in ("signer", "recipient")}
    forged = of.build(of.FORMAT_RESULT, hdr, {"outcome": {}}, signer=evil,
                      recipient=node.center)
    r = api.c.post("/offline/results", headers=api.op, content=forged)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "bad_signature"

    # не тот тип файла и мусор
    r = api.c.post("/offline/results", headers=api.op, content=job)
    assert r.status_code == 422 and "ожидается файл результата" in r.json()["detail"]["message"]
    r = api.c.post("/offline/results", headers=api.op, content=b"garbage")
    assert r.status_code == 422
    # прогон по-прежнему ждёт настоящий результат
    assert _import(api, result)["status"] == "done"


def test_export_rules(offline, stack):
    api, rec, _app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id)
    _export(api, run_id)
    # второй раз выгрузить нельзя, но можно скачать тот же файл
    r = api.c.post(f"/runs/{run_id}/offline/export", headers=api.op)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "already_exported"
    again = api.c.get(f"/runs/{run_id}/offline/job", headers=api.op)
    assert again.status_code == 200
    assert of.parse(again.content, of.FORMAT_JOB).header["run_id"] == run_id
    # аудитор (без run_scan) выгрузить не может
    aud = api.user("aud", "auditor")
    run2 = _start(api, eid, node_id)
    r = api.c.post(f"/runs/{run2}/offline/export", headers=aud)
    assert r.status_code == 403
    # прогон центра (без узла) выгрузить нельзя
    r = api.c.post(f"/engagements/{eid}/runs", headers=api.op,
                   json={"targets": ["10.1.0.7"], "modules": ["discovery"]})
    local = r.json()["id"]
    r = api.c.post(f"/runs/{local}/offline/export", headers=api.op)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "node_not_offline"


def test_node_key_required_and_guarded(stack, tmp_path):
    api, _rec, _app = stack
    eid = api.engagement("10.0.0.0/8")
    node_id = api.c.post("/nodes", headers=api.admin,
                         json={"name": "Контур", "scope": ["10.2.0.0/24"],
                               "mode": "offline"}).json()["id"]
    run_id = _start(api, eid, node_id, targets=("10.2.0.5",))
    r = api.c.post(f"/runs/{run_id}/offline/export", headers=api.op)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "node_key_missing"
    # ключ центра вместо ключа узла не принимается
    r = api.c.put(f"/nodes/{node_id}/public-key", headers=api.admin,
                  json={"public_key": _center_pub(api)})
    assert r.status_code == 422
    # оператору менять ключ узла нельзя
    op = api.user("op2", "operator")
    key = KeyPair.generate(ROLE_NODE).public.export()
    assert api.c.put(f"/nodes/{node_id}/public-key", headers=op,
                     json={"public_key": key}).status_code == 403
    assert api.c.put(f"/nodes/{node_id}/public-key", headers=api.admin,
                     json={"public_key": key}).status_code == 200
    # при невыполненном задании ключ не меняется
    _export(api, run_id)
    r = api.c.put(f"/nodes/{node_id}/public-key", headers=api.admin,
                  json={"public_key": KeyPair.generate(ROLE_NODE).public.export()})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "node_has_pending_jobs"


def test_cancel_and_expiry(offline, sqlite_factory):
    api, rec, app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id)
    job = _export(api, run_id)
    result = _run_on_node(node, job, rec)
    r = api.c.post(f"/runs/{run_id}/offline/cancel", headers=api.op)
    assert r.status_code == 200
    assert api.c.get(f"/runs/{run_id}", headers=api.op).json()["status"] == "stopped"
    r = api.c.post("/offline/results", headers=api.op, content=result)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "job_cancelled"
    # отменённое задание больше не скачать
    assert api.c.get(f"/runs/{run_id}/offline/job", headers=api.op).status_code == 409

    # просрочка: срок + запас истёк — прогон ошибкой, результат не примется
    run2 = _start(api, eid, node_id)
    job2 = _export(api, run2, valid_days=1)
    result2 = _run_on_node(node, job2, rec)
    runs: RunService = app.state.runs
    later = datetime.now(UTC) + timedelta(days=1) + oc.RESULT_GRACE + timedelta(hours=1)
    runs.recover_orphans(now=later)
    run = api.c.get(f"/runs/{run2}", headers=api.op).json()
    assert run["status"] == "failed" and "не загружен в срок" in run["error_message"]
    r = api.c.post("/offline/results", headers=api.op, content=result2)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "job_expired"


def test_offline_runs_survive_orphan_sweep(offline, sqlite_factory):
    """Прогон едет на носителе дни — сторож осиротевших прогонов его не трогает."""
    api, _rec, app, eid, node_id, _node = offline
    run_id = _start(api, eid, node_id)
    _export(api, run_id, valid_days=30)
    app.state.runs.recover_orphans(now=datetime.now(UTC) + timedelta(days=10))
    with sqlite_factory() as s:
        assert s.get(ScanRun, run_id).status == "running"
        assert s.scalar(select(OfflineJobRow.status)
                        .where(OfflineJobRow.run_id == run_id)) == "exported"


def test_job_for_one_node_rejected_by_another(offline, tmp_path):
    api, rec, _app, eid, node_id, _node = offline
    run_id = _start(api, eid, node_id)
    job = _export(api, run_id)
    on.init_node(tmp_path / "other", name="Другой", scope=["10.1.0.0/24"],
                 center_key=_center_pub(api))
    other = on.OfflineNode.load(tmp_path / "other")
    with pytest.raises(on.OfflineNodeError, match="для другого узла"):
        _run_on_node(other, job, rec)


def test_cli_node_commands(offline, tmp_path, capsys):
    """scanner node inspect / run-job на настоящем CLI: БД узла — свой SQLite."""
    from scanner.cli import main
    api, _rec, _app, eid, node_id, node = offline
    run_id = _start(api, eid, node_id)
    job_path = tmp_path / "media" / "job.scnjob"
    job_path.parent.mkdir()
    job_path.write_bytes(_export(api, run_id))
    home = ["--home", str(node.home)]
    db = ["--db-url", f"sqlite:///{tmp_path / 'node.db'}"]

    assert main(["node", "inspect", str(job_path), *home]) == 0
    out = capsys.readouterr().out
    assert "Задание проверено" in out and "10.1.0.5" in out and "10.1.0.0/24" in out

    # без подтверждения и без справочников — отказ
    assert main([*db, "node", "run-job", str(job_path), *home]) == 2
    assert main([*db, "node", "run-job", str(job_path), *home, "--confirm-authorized"]) == 2
    assert "ложно чистым" in capsys.readouterr().err
    # сети узла в тесте не пересекаются с целью: модули не запускаются, сеть не нужна
    node_json = node.home / on.NODE_FILE
    meta = json.loads(node_json.read_text())
    meta["scope"] = ["10.9.0.0/24"]
    node_json.write_text(json.dumps(meta))
    assert main([*db, "node", "run-job", str(job_path), *home, "--confirm-authorized",
                 "--allow-empty-reference", "--out", str(job_path.parent)]) == 0
    results = list(job_path.parent.glob("*.scnres"))
    assert len(results) == 1
    # второй запуск того же задания — отказ по журналу узла
    assert main([*db, "node", "run-job", str(job_path), *home, "--confirm-authorized",
                 "--allow-empty-reference"]) == 2
    assert main(["node", "show", *home]) == 0
    assert "выполнено заданий: 1" in capsys.readouterr().out
    res = _import(api, results[0].read_bytes())
    assert res["run_id"] == run_id and res["findings"] == 0
