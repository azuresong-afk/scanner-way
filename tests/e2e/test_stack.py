"""Сквозной сценарий на живом стеке Docker (запускает scripts/e2e.sh).

Шаги идут по порядку и опираются на результаты предыдущих:
готовность → вход → договор и allowlist → отказ вне allowlist → прогон по
стенду-цели → находки и сервисы → постраничный список → отчёты HTML/PDF/Word/
JSON → падение API во время прогона и «Прервано» → повтор прогона →
резервная копия и восстановление из неё.

Без SCANNER_E2E_URL модуль пропускается — обычный `pytest` его не трогает.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest

URL = os.environ.get("SCANNER_E2E_URL")
pytestmark = [pytest.mark.e2e,
              pytest.mark.skipif(not URL, reason="нужен живой стек: scripts/e2e.sh")]

TARGET = os.environ.get("SCANNER_E2E_TARGET", "172.29.250.10")
LAB = os.environ.get("SCANNER_E2E_LAB", "172.29.250.0/24")
STACK_DIR = Path(os.environ.get("SCANNER_E2E_DIR", "."))
ARTIFACTS = Path(os.environ.get("SCANNER_E2E_ARTIFACTS", "e2e-artifacts"))
RUN_TIMEOUT = float(os.environ.get("SCANNER_E2E_RUN_TIMEOUT", "900"))
FINISHED = {"done", "partial", "failed", "stopped", "interrupted"}

S: dict = {}          # состояние сценария между шагами


def compose(*args: str, timeout: float = 600) -> str:
    """docker compose в каталоге стека e2e (COMPOSE_FILE/PROJECT — из e2e.sh)."""
    r = subprocess.run(["docker", "compose", *args], check=False, cwd=STACK_DIR,
                       capture_output=True,
                       text=True, timeout=timeout)
    assert r.returncode == 0, f"docker compose {' '.join(args)}: {r.stdout}\n{r.stderr}"
    return r.stdout


def script(name: str, *args: str, timeout: float = 900) -> str:
    r = subprocess.run(["sh", f"scripts/{name}", *args], check=False, cwd=STACK_DIR,
                       capture_output=True, text=True, timeout=timeout,
                       env={**os.environ})
    assert r.returncode == 0, f"{name}: {r.stdout}\n{r.stderr}"
    return r.stdout


@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=f"{URL}/api", timeout=120) as c:
        yield c


def wait_ready(api: httpx.Client, timeout: float = 300) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            r = api.get("/health/ready")
            if r.status_code == 200:
                return
            last = f"{r.status_code} {r.text[:200]}"
        except httpx.HTTPError as e:
            last = repr(e)
        time.sleep(2)
    pytest.fail(f"API не готов за {timeout} с: {last}")


OPERATOR = "e2e-operator"


def token(api: httpx.Client, username: str, password: str) -> dict:
    r = api.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def login(api: httpx.Client) -> None:
    """S["admin"] — администратор (договоры, allowlist, пользователи);
    S["h"] — оператор (прогоны, отчёты): роли разделены, как в работе."""
    S["admin"] = token(api, os.environ["SCANNER_E2E_USER"], os.environ["SCANNER_E2E_PASSWORD"])
    if "op_ready" in S:
        S["h"] = token(api, OPERATOR, os.environ["SCANNER_E2E_OP_PASSWORD"])


def get_run(api: httpx.Client, run_id: int) -> dict:
    r = api.get(f"/runs/{run_id}", headers=S["h"])
    assert r.status_code == 200, r.text
    return r.json()


def wait_run(api: httpx.Client, run_id: int, statuses=FINISHED,
             timeout: float = RUN_TIMEOUT, poll: float = 2) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = get_run(api, run_id)
        if run["status"] in statuses:
            return run
        time.sleep(poll)
    pytest.fail(f"прогон {run_id} не дошёл до {statuses} за {timeout} с: {run}")


def save(name: str, content: bytes) -> Path:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    p = ARTIFACTS / name
    p.write_bytes(content)
    return p


# ---------- шаги ----------
def test_01_ready_and_login(api):
    wait_ready(api)
    assert api.get("/health").status_code == 200
    assert api.post("/auth/token", json={"username": "admin",
                                         "password": "wrong-password-1"}).status_code == 401
    login(api)
    assert api.get("/me", headers=S["admin"]).json()["username"] == os.environ["SCANNER_E2E_USER"]
    r = api.post("/users", headers=S["admin"],
                 json={"username": OPERATOR, "password": os.environ["SCANNER_E2E_OP_PASSWORD"],
                       "roles": ["operator"]})
    assert r.status_code == 201, r.text
    S["op_ready"] = True
    login(api)
    # у администратора нет права запускать прогоны — только у оператора
    assert api.post("/engagements/1/runs", headers=S["admin"],
                    json={"targets": [TARGET], "modules": ["discovery"]}).status_code == 403


def test_02_engagement_and_allowlist(api):
    r = api.post("/engagements", headers=S["admin"],
                 json={"name": "e2e основной", "client": "стенд", "contract_ref": "E2E-1"})
    assert r.status_code == 201, r.text
    S["eid"] = r.json()["id"]
    r = api.post(f"/engagements/{S['eid']}/allowlist", headers=S["admin"],
                 json={"cidr": f"{TARGET}/32", "note": "стенд e2e"})
    assert r.status_code == 201, r.text


def test_03_target_outside_allowlist_is_refused(api):
    outside = TARGET.rsplit(".", 1)[0] + ".99"
    r = api.post(f"/engagements/{S['eid']}/runs", headers=S["h"],
                 json={"targets": [outside], "modules": ["discovery"]})
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["denied_targets"][0]["target"] == outside


def test_04_scan_lab_target(api):
    r = api.post(f"/engagements/{S['eid']}/runs", headers=S["h"],
                 json={"targets": [TARGET], "modules": ["discovery", "vuln"],
                       "vuln_engine": "nuclei", "rate_profile": "normal",
                       "name": "e2e: стенд"})
    assert r.status_code == 202, r.text
    S["run"] = r.json()["id"]
    run = wait_run(api, S["run"])
    if run["status"] == "partial" and os.environ.get("SCANNER_E2E_EXPECT_FINDINGS") != "1":
        # «Частично» допустимо, только если не отработал Nuclei (например, шаблоны не
        # скачались) — и это явно видно в покрытии прогона, а не «чисто».
        cov = api.get(f"/runs/{S['run']}/coverage", headers=S["h"]).json()
        gaps = [e for e in cov["entries"] if e["status"] not in ("completed", "not_applicable")]
        assert gaps and all(e["module"] == "vuln" for e in gaps), cov
        assert next(e for e in cov["entries"] if e["module"] == "discovery")["status"] == "completed"
    else:
        assert run["status"] == S["run_status"], run
    S["run_status"] = run["status"]
    services = api.get(f"/runs/{S['run']}/services", headers=S["h"]).json()
    http = [s for s in services if s["host"] == TARGET and s["port"] == 80]
    assert http, f"discovery не нашёл 80/tcp на {TARGET}: {services}"
    S["product"] = f"{http[0]['product']} {http[0]['version']}"
    # Находки nuclei по Apache 2.4.49 зависят от набора шаблонов и
    # справочников, поэтому строгая проверка — по флагу.
    total = int(api.get(f"/runs/{S['run']}/findings", headers=S["h"],
                        params={"limit": 1}).headers["X-Total-Count"])
    S["findings"] = total
    vulns = int(api.get(f"/runs/{S['run']}/findings", headers=S["h"],
                        params={"limit": 1, "module": "vuln"}).headers["X-Total-Count"])
    if os.environ.get("SCANNER_E2E_EXPECT_FINDINGS") == "1":
        assert vulns > 0, "nuclei не дал ни одной находки по стенду"


def test_05_paged_lists_and_summary(api):
    total = S["findings"]
    page = api.get(f"/runs/{S['run']}/findings", headers=S["h"],
                   params={"limit": 2, "offset": 0, "sort": "severity"})
    assert page.status_code == 200 and int(page.headers["X-Total-Count"]) == total
    assert len(page.json()) == min(2, total)
    summary = api.get(f"/runs/{S['run']}/findings/summary", headers=S["h"]).json()
    assert summary["hosts"] >= 1
    assert sum(summary["counts"].values()) + summary["false_positives"] == total
    runs = api.get(f"/engagements/{S['eid']}/runs", headers=S["h"], params={"limit": 1})
    assert runs.headers["X-Total-Count"] == "1"     # отказ в шаге 03 прогон не создаёт
    assert runs.json()[0]["id"] == S["run"]


@pytest.mark.parametrize("fmt,ctype,magic", [
    ("html", "text/html", b"<"),
    ("pdf", "application/pdf", b"%PDF"),
    ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     b"PK"),
    ("json", "application/json", b"{"),
])
def test_06_reports(api, fmt, ctype, magic):
    for variant in ("full", "brief"):
        r = api.get(f"/runs/{S['run']}/report", headers=S["h"],
                    params={"format": fmt, "variant": variant})
        assert r.status_code == 200, r.text[:500]
        assert r.headers["content-type"].startswith(ctype)
        assert r.content.lstrip()[:len(magic)] == magic
        assert len(r.content) > 1000
        save(f"report-{variant}.{fmt}", r.content)
    if fmt == "json":
        body = r.json()
        assert TARGET in str(body)


def test_07_api_crash_during_run_marks_it_interrupted(api):
    """Прогон идёт → процесс API убит (SIGKILL) → после старта прогон
    «Прервано» с причиной, а не «Выполняется» навсегда."""
    r = api.post("/engagements", headers=S["admin"], json={"name": "e2e перезапуск"})
    S["eid2"] = r.json()["id"]
    assert api.post(f"/engagements/{S['eid2']}/allowlist", headers=S["admin"],
                    json={"cidr": LAB, "note": "сеть стенда"}).status_code == 201
    # вся сеть стенда с бережным профилем — прогон заведомо дольше нескольких секунд
    r = api.post(f"/engagements/{S['eid2']}/runs", headers=S["h"],
                 json={"targets": [LAB], "modules": ["discovery"],
                       "rate_profile": "gentle", "name": "e2e: будет прерван"})
    assert r.status_code == 202, r.text
    rid = r.json()["id"]
    run = wait_run(api, rid, statuses={"running", *FINISHED}, timeout=120, poll=0.3)
    assert run["status"] == "running", f"прогон закончился раньше падения: {run}"

    compose("kill", "-s", "SIGKILL", "app")
    compose("up", "-d", "--wait", "app")
    wait_ready(api)
    run = wait_run(api, rid, timeout=120)
    assert run["status"] == "interrupted", run
    assert run["error_message"], run
    S["interrupted"] = rid


def test_08_retry_interrupted_run(api):
    r = api.post(f"/runs/{S['interrupted']}/retry", headers=S["h"])
    assert r.status_code == 202, r.text
    new = r.json()
    assert new["retry_of"] == S["interrupted"] and new["id"] != S["interrupted"]
    # повтор — обычный прогон: его можно остановить
    wait_run(api, new["id"], statuses={"running", *FINISHED}, timeout=120, poll=0.5)
    api.post(f"/runs/{new['id']}/stop", headers=S["h"])
    assert wait_run(api, new["id"], timeout=300)["status"] in {"stopped", "done", "partial"}
    # успешно завершённый прогон повторять нельзя (повтор — только для
    # «Ошибка» / «Частично» / «Прервано» / «Остановлен»)
    assert get_run(api, S["run"])["status"] == S["run_status"]
    if S["run_status"] == "done":
        assert api.post(f"/runs/{S['run']}/retry", headers=S["h"]).status_code == 409


def test_09_backup_and_restore(api):
    backup = STACK_DIR / "backups" / "e2e"
    out = script("backup.sh", "backups/e2e")
    assert (backup / "db.dump").stat().st_size > 0, out
    assert "alembic_revision=" in (backup / "manifest.txt").read_text()

    # после копии появляется договор, которого в копии нет
    r = api.post("/engagements", headers=S["admin"], json={"name": "e2e после копии"})
    assert r.status_code == 201
    # без --yes восстановление ничего не меняет
    r = subprocess.run(["sh", "scripts/restore.sh", "backups/e2e"], check=False,
                       cwd=STACK_DIR,
                       capture_output=True, text=True)
    assert r.returncode == 2

    script("restore.sh", "backups/e2e", "--yes")
    wait_ready(api)
    login(api)
    names = {e["name"] for e in api.get("/engagements", headers=S["admin"]).json()}
    assert "e2e основной" in names and "e2e после копии" not in names
    run = get_run(api, S["run"])
    assert run["status"] == S["run_status"]
    total = api.get(f"/runs/{S['run']}/findings", headers=S["h"],
                    params={"limit": 1}).headers["X-Total-Count"]
    assert int(total) == S["findings"]
