"""Нагрузочный замер списков находок на синтетических данных.

Создаёт в ОТДЕЛЬНОЙ (тестовой) базе договор и прогон с hosts × per_host
находками и меряет время ответов API: страница находок с фильтром и
сортировкой, сортировка по приоритету, поиск, сводка прогона, страница
прогонов. Сеть и сканирование не используются.

    python scripts/load_test.py --url postgresql+psycopg://u:p@127.0.0.1:5432/scanner_load \\
        --hosts 1000 --per-host 1000          # 1 млн находок

База должна быть с актуальной схемой (alembic upgrade head). НЕ запускайте
на боевой базе: скрипт добавляет миллион строк.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import insert, text

from scanner.core.db import FindingRow

SEVERITIES = ("critical", "high", "medium", "low", "info")
CVSS = {"critical": 9.8, "high": 7.5, "medium": 5.0, "low": 2.0, "info": None}


def bulk_insert(factory, engagement_id: int, scan_run_id: int, *, hosts: int,
                per_host: int, batch: int = 20000) -> int:
    """Вставить hosts × per_host синтетических находок пачками."""
    rows, n = [], 0

    def flush():
        nonlocal rows
        if rows:
            with factory() as s, s.begin():
                s.execute(insert(FindingRow), rows)
            rows = []

    for h in range(hosts):
        host = f"10.{(h >> 16) & 255}.{(h >> 8) & 255}.{h & 255}"
        for i in range(per_host):
            sev = SEVERITIES[i % 5]
            vid = f"CVE-2024-{(h * per_host + i) % 99999:05d}"
            port = 1 + i % 1000
            key = hashlib.sha256(f"{host}|{port}|{vid}|vuln|{i}".encode()).hexdigest()
            rows.append({
                "engagement_id": engagement_id, "scan_run_id": scan_run_id,
                "module": "vuln" if i % 3 else "config_audit", "finding_type": "vuln",
                "host": host, "port": port, "vuln_id": vid, "cve_ids": [vid],
                "bdu_ids": [f"BDU:2024-{i % 9999:05d}"] if i % 4 == 0 else [],
                "title": f"Синтетическая уязвимость {i} OpenSSH", "severity": sev,
                "cvss": CVSS[sev], "evidence": None, "status": "open", "dedup_key": key,
                "remediation": None})
            n += 1
            if len(rows) >= batch:
                flush()
    flush()
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", required=True, help="SQLAlchemy URL тестовой БД")
    ap.add_argument("--hosts", type=int, default=1000)
    ap.add_argument("--per-host", type=int, default=1000)
    ap.add_argument("--run", type=int, help="замерить уже заполненный прогон (без вставки)")
    args = ap.parse_args()

    from fastapi.testclient import TestClient

    from scanner.api.main import create_app
    from scanner.api.settings import ApiSettings
    from scanner.core import repository as repo
    from scanner.core.db import make_engine, make_session_factory, session_scope
    from scanner.core.orchestrator import inline_executor
    from scanner.reporting.remediation import RemediationResolver

    factory = make_session_factory(make_engine(args.url))
    if args.run:
        with session_scope(factory) as s:
            rid = args.run
            eid = repo.get_scan_run(s, rid).engagement_id
            n = s.scalar(text("SELECT count(*) FROM findings WHERE scan_run_id = :r"), {"r": rid})
    else:
        with session_scope(factory) as s:
            eid = repo.create_engagement(s, name=f"load-test {time.strftime('%F %T')}")
            rid = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"])
            repo.set_scan_run_status(s, rid, "done")
            for k in range(200):
                r = repo.create_scan_run(s, engagement_id=eid, modules=["vuln"], name=f"run {k}")
                repo.set_scan_run_status(s, r, "done")
        t = time.perf_counter()
        n = bulk_insert(factory, eid, rid, hosts=args.hosts, per_host=args.per_host)
        print(f"вставлено находок: {n} за {time.perf_counter() - t:.1f} с")
    with factory() as s, s.begin():
        s.execute(text("ANALYZE findings"))

    user = f"load{int(time.time())}"
    password = "load-test-password-1"
    settings = ApiSettings(secret="l" * 40, run_heartbeat_seconds=0,
                           scheduler_tick_seconds=0, feeds_tick_seconds=0,
                           notify_tick_seconds=0)
    app = create_app(session_factory=factory, settings=settings, registry={},
                     executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    from scanner.api.rbac import seed_rbac, set_user_roles
    from scanner.api.security import hash_password
    from scanner.core.db import User
    with session_scope(factory) as s:
        seed_rbac(s)
        u = User(username=user, password_hash=hash_password(password), is_active=True)
        s.add(u)
        s.flush()
        set_user_roles(s, u.id, ["auditor"])
    results = {}
    with TestClient(app) as c:
        tok = c.post("/auth/token", json={"username": user, "password": password}).json()
        h = {"Authorization": f"Bearer {tok['access_token']}"}

        def timed(name, url, **params):
            t0 = time.perf_counter()
            r = c.get(url, headers=h, params=params)
            dt = time.perf_counter() - t0
            assert r.status_code == 200, r.text
            results[name] = {"seconds": round(dt, 3),
                             "total": r.headers.get("X-Total-Count")}
            print(f"{name:<44} {dt:7.3f} с  всего={r.headers.get('X-Total-Count', '-')}")

        base = f"/runs/{rid}/findings"
        timed("страница 1, опасные сначала (первый вызов)", base, limit=50, sort="severity",
              include_info="false")
        timed("страница 1, опасные сначала (повтор)", base, limit=50, sort="severity",
              include_info="false")
        timed("страница 200, опасные сначала", base, limit=50, offset=9950, sort="severity")
        timed("фильтр critical + модуль vuln", base, limit=50, severity="critical",
              module="vuln", sort="cvss")
        timed("поиск по подстроке «CVE-2024-0042»", base, limit=50, q="CVE-2024-0042")
        timed("хост 10.0.1.17", base, limit=50, host="10.0.1.17")
        timed("сортировка по приоритету", base, limit=50, sort="priority",
              include_info="false")
        timed("сводка прогона", f"{base}/summary")
        timed("страница прогонов", f"/engagements/{eid}/runs", limit=25)
    print(json.dumps({"findings": n, "results": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
