"""Выгрузка журнала аудита в CSV/JSON: фильтры, права, неизменяемость."""
# ruff: noqa: F811 — фикстуры api/rec/cves импортируются из test_api
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from scanner.core import audit_export as ax
from scanner.core.db import AuditLogRow
from tests.test_api import api, cves, rec  # noqa: F401 — фикстуры

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _seed(sqlite_factory):
    """Четыре события с известным временем, до служебных записей теста."""
    events = [
        (datetime(2026, 10, 1, 9, 0, tzinfo=UTC), "user:op", "scan_start", "run:1", "ok", None),
        (datetime(2026, 10, 1, 12, 0, tzinfo=UTC), "user:op", "export", "scan_run:1", "ok",
         {"format": "pdf"}),
        (datetime(2026, 10, 2, 8, 30, tzinfo=UTC), "scanner", "deny", "=cmd|' /C calc'!A0",
         "not_in_allowlist", {"note": "Цель вне договора"}),
        (datetime(2026, 10, 3, 23, 59, tzinfo=UTC), "user:op", "scan_start", "run:2", "ok", None),
    ]
    with sqlite_factory() as s, s.begin():
        for ts, subj, action, target, result, details in events:
            s.add(AuditLogRow(ts=ts, subject=subj, action=action, target=target,
                              result=result, details=details))


def _count(sqlite_factory, action=None) -> int:
    q = select(func.count()).select_from(AuditLogRow)
    if action:
        q = q.where(AuditLogRow.action == action)
    with sqlite_factory() as s:
        return s.scalar(q)


def test_export_json_filters_by_actions_and_range(api, sqlite_factory):
    _seed(sqlite_factory)
    r = api.c.get("/audit/export", headers=api.admin, params={
        "format": "json", "action": ["scan_start", "deny"],
        "since": "2026-10-01T10:00:00Z", "until": "2026-10-03T23:59:00Z"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert 'attachment; filename="audit-' in r.headers["content-disposition"]
    doc = r.json()
    # 09:00 — раньше начала; 23:59 — конец диапазона не включается
    assert [(e["action"], e["target"]) for e in doc["events"]] == [
        ("deny", "=cmd|' /C calc'!A0")]
    assert doc["count"] == 1 == int(r.headers["x-audit-count"])
    assert doc["exported_by"] == "user:root"
    assert doc["filters"]["actions"] == ["deny", "scan_start"]
    assert doc["filters"]["since"] == "2026-10-01T10:00:00+00:00"
    assert doc["events"][0]["details"] == {"note": "Цель вне договора"}
    assert doc["events"][0]["ts"] == "2026-10-02T08:30:00+00:00"


def test_export_csv_chronological_with_bom_and_formula_escaping(api, sqlite_factory):
    _seed(sqlite_factory)
    r = api.c.get("/audit/export", headers=api.admin, params={
        "format": "csv", "until": "2026-10-04T00:00:00+03:00"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert r.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert list(rows[0]) == list(ax.CSV_COLUMNS)
    # 2026-10-04 00:00 MSK = 2026-10-03 21:00 UTC: последнее событие (23:59 UTC) отсечено
    assert [x["action"] for x in rows] == ["scan_start", "export", "deny"]
    assert rows[2]["target"] == "'=cmd|' /C calc'!A0"          # не формула для Excel
    assert json.loads(rows[1]["details"]) == {"format": "pdf"}
    assert rows[0]["details"] == ""


def test_list_accepts_same_filters(api, sqlite_factory):
    _seed(sqlite_factory)
    r = api.c.get("/audit", headers=api.admin, params={
        "action": ["scan_start", "export"], "since": "2026-10-01T10:00:00Z"})
    assert r.status_code == 200, r.text
    assert [(e["action"], e["target"]) for e in r.json()] == [
        ("scan_start", "run:2"), ("export", "scan_run:1")]
    # старая форма с одним action продолжает работать
    r = api.c.get("/audit?action=deny", headers=api.admin)
    assert [e["action"] for e in r.json()] == ["deny"]


def test_actions_endpoint_lists_distinct_actions(api, sqlite_factory):
    _seed(sqlite_factory)
    r = api.c.get("/audit/actions", headers=api.admin)
    assert r.status_code == 200
    acts = r.json()
    assert acts == sorted(set(acts))
    assert {"scan_start", "export", "deny", "login"} <= set(acts)


def test_export_is_read_only_and_audited(api, sqlite_factory):
    _seed(sqlite_factory)
    with sqlite_factory() as s:
        before = [tuple(r) for r in s.execute(select(
            AuditLogRow.id, AuditLogRow.ts, AuditLogRow.action, AuditLogRow.target))]
    r = api.c.get("/audit/export", headers=api.admin,
                  params={"format": "csv", "action": "deny"})
    assert r.status_code == 200
    with sqlite_factory() as s:
        after = [tuple(r) for r in s.execute(select(
            AuditLogRow.id, AuditLogRow.ts, AuditLogRow.action, AuditLogRow.target))]
        last = s.scalars(select(AuditLogRow).order_by(AuditLogRow.id.desc())).first()
    assert after[:len(before)] == before                      # старые записи нетронуты
    assert len(after) == len(before) + 1                       # +1: отметка о выгрузке
    assert (last.subject, last.action, last.result) == ("user:root", "audit_export", "ok")
    assert last.details["format"] == "csv" and last.details["returned"] == 1
    assert last.details["actions"] == ["deny"]


@pytest.mark.parametrize("who,code", [("auditor", 200), ("operator", 403)])
def test_export_rbac(api, sqlite_factory, who, code):
    h = api.user("u1", who)
    for path in ("/audit/export", "/audit/export?format=json", "/audit/actions"):
        assert api.c.get(path, headers=h).status_code == code, path
    if code == 403:
        assert _count(sqlite_factory, "audit_export") == 0
    assert api.c.get("/audit/export").status_code == 401


def test_export_validates_input(api):
    r = api.c.get("/audit/export", headers=api.admin, params={
        "since": "2026-10-02T00:00:00Z", "until": "2026-10-01T00:00:00Z"})
    assert r.status_code == 422 and "раньше" in r.json()["detail"]
    assert api.c.get("/audit/export?format=xlsx", headers=api.admin).status_code == 422
    assert api.c.get("/audit/export?since=вчера", headers=api.admin).status_code == 422


def test_export_refuses_too_many_rows(api, sqlite_factory, monkeypatch):
    _seed(sqlite_factory)
    monkeypatch.setattr(ax, "MAX_EXPORT_ROWS", 2)
    r = api.c.get("/audit/export", headers=api.admin)
    assert r.status_code == 413 and "сузьте" in r.json()["detail"]
    with sqlite_factory() as s:
        last = s.scalars(select(AuditLogRow).order_by(AuditLogRow.id.desc())).first()
    assert (last.action, last.result) == ("audit_export", "too_large")


def test_naive_datetimes_are_utc():
    flt = ax.AuditFilter(since=datetime(2026, 10, 1, 12, 0), actions=["b", "a", "a", ""])
    assert flt.since == T0 and flt.actions == ("a", "b")
