"""Прогоны по расписанию и имена прогонов по выбранным опциям."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scanner.core.db import ScanRun, ScanSchedule
from scanner.core.naming import clean_name, run_title
from scanner.core.orchestrator import inline_executor
from scanner.core.schedule import ScheduleError, ScheduleSpec, next_occurrence
from tests.test_api import Api, DeferredExecutor, Recorder, _make, _run

MSK = "Europe/Moscow"


# ---------- имена ----------
def test_run_title_from_options():
    assert run_title(["discovery", "vuln"], ["10.0.0.0/24"]) == \
        "Обнаружение + Nuclei · 10.0.0.0/24"
    assert run_title(["vuln", "auth_inventory", "config_audit"],
                     ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]) == \
        "Nuclei + учётная запись + конфигурации · 10.0.0.5, 10.0.0.6 и ещё 2"
    assert run_title(["auth_inventory"], ["10.0.0.5"]) == "По учётной записи · 10.0.0.5"
    assert run_title(["cred_audit"], []) == "Аудит паролей"
    assert run_title([], []) == "Прогон"


def test_clean_name():
    assert clean_name("  ночной   скан ") == "ночной скан"
    assert clean_name("   ") is None
    assert len(clean_name("я" * 500)) == 200


# ---------- график ----------
def _utc(*a) -> datetime:
    return datetime(*a, tzinfo=UTC)


def test_daily_in_local_timezone():
    spec = ScheduleSpec(kind="daily", timezone=MSK, time_of_day="03:30")
    # 03:30 МСК = 00:30 UTC
    assert next_occurrence(spec, _utc(2026, 10, 29, 0, 0)) == _utc(2026, 10, 29, 0, 30)
    assert next_occurrence(spec, _utc(2026, 10, 29, 0, 30)) == _utc(2026, 10, 30, 0, 30)


def test_weekly_and_monthly():
    weekly = ScheduleSpec(kind="weekly", timezone="UTC", time_of_day="22:00",
                          weekdays=[0, 4])          # пн и пт
    # 2026-10-29 — четверг
    assert next_occurrence(weekly, _utc(2026, 10, 29, 12)) == _utc(2026, 10, 30, 22)
    assert next_occurrence(weekly, _utc(2026, 10, 30, 23)) == _utc(2026, 11, 2, 22)
    monthly = ScheduleSpec(kind="monthly", timezone="UTC", time_of_day="01:00",
                           month_day=31)
    # в феврале 31-го нет — запуск в последний день месяца
    assert next_occurrence(monthly, _utc(2027, 2, 1)) == _utc(2027, 2, 28, 1)
    assert next_occurrence(monthly, _utc(2027, 2, 28, 2)) == _utc(2027, 3, 31, 1)


def test_once():
    spec = ScheduleSpec(kind="once", timezone="UTC", run_at=_utc(2026, 11, 1, 10))
    assert next_occurrence(spec, _utc(2026, 10, 29)) == _utc(2026, 11, 1, 10)
    assert next_occurrence(spec, _utc(2026, 11, 1, 10)) is None


@pytest.mark.parametrize("spec", [
    ScheduleSpec(kind="daily", timezone="UTC", time_of_day="25:00"),
    ScheduleSpec(kind="weekly", timezone="UTC", time_of_day="10:00"),
    ScheduleSpec(kind="monthly", timezone="UTC", time_of_day="10:00", month_day=0),
    ScheduleSpec(kind="once", timezone="UTC"),
    ScheduleSpec(kind="daily", timezone="Mars/Olympus", time_of_day="10:00"),
])
def test_invalid_specs(spec):
    with pytest.raises(ScheduleError):
        spec.validate()


# ---------- API ----------
@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def cves():
    return ["CVE-2016-6210"]


@pytest.fixture
def api(sqlite_factory, rec, cves):
    with TestClient(_make(sqlite_factory, rec, cves, inline_executor())) as c:
        yield Api(c)


@pytest.fixture
def deferred():
    return DeferredExecutor()


@pytest.fixture
def api_deferred(sqlite_factory, rec, cves, deferred):
    with TestClient(_make(sqlite_factory, rec, cves, deferred)) as c:
        yield Api(c)


def _schedule(api, eid, headers, **kw):
    body = {"targets": ["10.0.0.0/30"], "modules": ["discovery", "vuln"],
            "kind": "daily", "time_of_day": "03:00", "timezone": MSK, **kw}
    return api.c.post(f"/engagements/{eid}/schedules", headers=headers, json=body)


def _runs(sqlite_factory) -> list[ScanRun]:
    with sqlite_factory() as s:
        return list(s.scalars(select(ScanRun).order_by(ScanRun.id)))


def _sched(sqlite_factory, sid) -> ScanSchedule:
    with sqlite_factory() as s:
        return s.get(ScanSchedule, sid)


def _due(sqlite_factory, sid) -> datetime:
    n = _sched(sqlite_factory, sid).next_run_at
    return (n if n.tzinfo else n.replace(tzinfo=UTC)) + timedelta(seconds=1)


def test_run_gets_name_from_options(api):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.1"])
    assert r.status_code == 202, r.text
    assert r.json()["name"] == "Обнаружение + Nuclei · 10.0.0.1"
    assert r.json()["targets"] == ["10.0.0.1"]
    r = _run(api, eid, op, ["10.0.0.1"], name="  Ночная проверка DMZ ")
    assert r.json()["name"] == "Ночная проверка DMZ"
    listed = api.c.get(f"/engagements/{eid}/runs", headers=op).json()
    assert [x["name"] for x in listed] == ["Обнаружение + Nuclei · 10.0.0.1",
                                           "Ночная проверка DMZ"]


def test_legacy_run_without_name_gets_label(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    rid = _run(api, eid, op, ["10.0.0.1"]).json()["id"]
    with sqlite_factory() as s:     # как прогон до миграции 0005
        run = s.get(ScanRun, rid)
        run.name, run.targets = None, []
        s.commit()
    assert api.c.get(f"/runs/{rid}", headers=op).json()["name"] == "Обнаружение + Nuclei"


def test_schedule_create_and_permissions(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    auditor = api.user("aud", "auditor")
    assert _schedule(api, eid, auditor).status_code == 403
    assert _schedule(api, eid, api.admin).status_code == 403     # admin не сканирует
    # модуль cred_audit — только с отдельным правом
    assert _schedule(api, eid, op, modules=["cred_audit"]).status_code == 403
    assert _schedule(api, eid, op, targets=["192.168.0.1"]).status_code == 422
    assert _schedule(api, eid, op, time_of_day="3am").status_code == 422
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert _schedule(api, eid, op, kind="once", run_at=past).status_code == 422

    r = _schedule(api, eid, op, vuln_engine="nuclei", modules=["discovery"])
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["title"] == "Обнаружение + Nuclei · 10.0.0.0/30"
    assert s["modules"] == ["discovery", "vuln"]
    assert s["enabled"] and s["next_run_at"]
    assert s["timezone"] == MSK
    listed = api.c.get(f"/engagements/{eid}/schedules", headers=auditor).json()
    assert [x["id"] for x in listed] == [s["id"]]
    actions = [a[1] for a in api.audit(sqlite_factory)]
    assert "schedule_create" in actions


def test_scheduler_fires_due_schedule_once(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    sid = _schedule(api, eid, op, name="Ежедневный DMZ").json()["id"]
    scheduler = api.c.app.state.scheduler
    due = _due(sqlite_factory, sid)

    assert scheduler.tick(due - timedelta(minutes=5)) == {}
    assert scheduler.tick(due) == {sid: "queued"}
    assert scheduler.tick(due) == {}       # то же срабатывание дважды не ставится
    runs = _runs(sqlite_factory)
    assert len(runs) == 1
    run = runs[0]
    assert run.schedule_id == sid and run.name == "Ежедневный DMZ"
    assert run.status == "done" and run.targets == ["10.0.0.0/30"]
    sch = _sched(sqlite_factory, sid)
    assert sch.last_result == "queued" and sch.enabled
    nxt = sch.next_run_at.replace(tzinfo=UTC)
    assert nxt - due > timedelta(hours=23)
    out = api.c.get(f"/schedules/{sid}", headers=op).json()
    assert out["last_run_id"] == run.id
    log = api.audit(sqlite_factory)
    assert (f"schedule:{sid}", "schedule_fire", f"schedule:{sid}", "ok") in log


def test_once_schedule_disables_itself(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    at = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    sid = _schedule(api, eid, op, kind="once", run_at=at).json()["id"]
    assert api.c.app.state.scheduler.tick(_due(sqlite_factory, sid)) == {sid: "queued"}
    sch = _sched(sqlite_factory, sid)
    assert not sch.enabled and sch.next_run_at is None


def test_overlap_is_skipped(api_deferred, sqlite_factory, deferred):
    api = api_deferred
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    sid = _schedule(api, eid, op).json()["id"]
    scheduler = api.c.app.state.scheduler
    assert scheduler.tick(_due(sqlite_factory, sid)) == {sid: "queued"}
    # первый прогон ещё в очереди — следующее срабатывание пропускается
    assert scheduler.tick(_due(sqlite_factory, sid)) == {sid: "skipped_overlap"}
    assert len(_runs(sqlite_factory)) == 1
    assert _sched(sqlite_factory, sid).enabled
    deferred.run_all()
    assert scheduler.tick(_due(sqlite_factory, sid)) == {sid: "queued"}


def test_owner_without_rights_disables_schedule(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    sid = _schedule(api, eid, op).json()["id"]
    uid = api.c.get("/me", headers=op).json()["id"]
    r = api.c.put(f"/users/{uid}/roles", headers=api.admin, json={"roles": ["auditor"]})
    assert r.status_code == 200, r.text
    assert api.c.app.state.scheduler.tick(_due(sqlite_factory, sid)) == \
        {sid: "skipped_no_rights"}
    assert _runs(sqlite_factory) == []
    sch = _sched(sqlite_factory, sid)
    assert not sch.enabled and sch.last_result == "skipped_no_rights"


def test_toggle_update_run_now_delete(api, sqlite_factory):
    eid = api.engagement("10.0.0.0/24")
    op = api.user("op", "operator")
    sid = _schedule(api, eid, op).json()["id"]

    off = api.c.patch(f"/schedules/{sid}", headers=op, json={"enabled": False}).json()
    assert not off["enabled"] and off["next_run_at"] is None
    on = api.c.patch(f"/schedules/{sid}", headers=op, json={"enabled": True}).json()
    assert on["enabled"] and on["next_run_at"]

    r = api.c.put(f"/schedules/{sid}", headers=op,
                  json={"targets": ["10.0.0.9"], "modules": ["discovery"],
                        "kind": "weekly", "time_of_day": "23:15", "weekdays": [5, 6],
                        "timezone": "UTC"})
    assert r.status_code == 200, r.text
    upd = r.json()
    assert upd["kind"] == "weekly" and upd["weekdays"] == [5, 6]
    assert upd["title"] == "Инвентаризация · 10.0.0.9"
    assert datetime.fromisoformat(upd["next_run_at"]).weekday() in (5, 6)

    r = api.c.post(f"/schedules/{sid}/run", headers=op)
    assert r.status_code == 200, r.text
    runs = _runs(sqlite_factory)
    assert len(runs) == 1 and runs[0].schedule_id == sid
    assert r.json()["next_run_at"] == upd["next_run_at"]     # график не сдвинут

    assert api.c.delete(f"/schedules/{sid}", headers=op).status_code == 204
    assert api.c.get(f"/schedules/{sid}", headers=op).status_code == 404
    runs = _runs(sqlite_factory)
    assert len(runs) == 1 and runs[0].schedule_id is None    # прогон остался
