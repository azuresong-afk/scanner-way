"""Достоверность прогонов на живом стеке Docker (запускает scripts/e2e.sh).

Сценарии из полевых тестов на Kali / Debian 13:

1. Выключенный хост — прогон не «успешный», «Хост недоступен, проверка не
   выполнена» в API и в отчёте, нигде «уязвимостей не выявлено».
2. Хост доступен, SSH молчит (таймаут) — «Частично», сетевые результаты есть,
   пробел покрытия и причина видны.
3/4. Debian 13 по SSH: пакеты собраны; без бюллетеней trixie — «Бэкпорты не
   учтены» в прогоне, отчёте и мастере справочников; бюллетени trixie
   загружаются одним действием, после чего исправленная бэкпортом CVE не
   активна, а неисправленная — находка «по бюллетеню вендора».
6. Прогоны по разным хостам/модулям — нет ложных «устранено»/«регрессия».
7. Повторная загрузка бюллетеней — без дублей.
Плюс профиль «Полная проверка Linux» и итоговый состав до запуска.

Без SCANNER_E2E_URL и стенда (SCANNER_E2E_SSH13 и др.) модуль пропускается.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import pytest

URL = os.environ.get("SCANNER_E2E_URL")
SSH13 = os.environ.get("SCANNER_E2E_SSH13")
SILENT = os.environ.get("SCANNER_E2E_SSH_SILENT")
DOWN = os.environ.get("SCANNER_E2E_DOWN")
SSH_PASSWORD = os.environ.get("SCANNER_E2E_SSH_PASSWORD", "")
SSH_PORT = int(os.environ.get("SCANNER_E2E_SSH_PORT", "22"))
SILENT_PORT = int(os.environ.get("SCANNER_E2E_SSH_SILENT_PORT", "22"))
# Выпуск ОС стенда с SSH: в Docker e2e — Debian 13 (trixie); при ручной проверке
# можно взять другой (например alpine:3.24 — образ linuxserver/openssh-server).
FAMILY, RELEASE = os.environ.get("SCANNER_E2E_SSH13_RELEASE", "debian:trixie").split(":")
SSH_PKG = {"debian": "openssh-server", "alpine": "openssh-server-pam"}[FAMILY]
pytestmark = [pytest.mark.e2e,
              pytest.mark.skipif(not (URL and SSH13 and SILENT and DOWN),
                                 reason="нужен живой стек со стендом: scripts/e2e.sh")]

STACK_DIR = Path(os.environ.get("SCANNER_E2E_DIR", "."))
ADVISORY_DIR = Path(os.environ.get("SCANNER_E2E_ADVISORY_DIR", str(STACK_DIR / "data" / "advisories")))
ARTIFACTS = Path(os.environ.get("SCANNER_E2E_ARTIFACTS", "e2e-artifacts"))
RUN_TIMEOUT = float(os.environ.get("SCANNER_E2E_RUN_TIMEOUT", "900"))
FINISHED = {"done", "partial", "failed", "stopped", "interrupted"}
MSG_DOWN = "Хост недоступен, проверка не выполнена"
CRED_USER = "e2e-cred-operator"

S: dict = {}


@pytest.fixture(scope="module")
def api():
    # SCANNER_E2E_API_URL — API без nginx (стек, поднятый вручную)
    base = os.environ.get("SCANNER_E2E_API_URL") or f"{URL}/api"
    with httpx.Client(base_url=base, timeout=180) as c:
        yield c


def token(api, username, password) -> dict:
    r = api.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def wait_run(api, rid: int, timeout: float = RUN_TIMEOUT) -> dict:
    deadline = time.monotonic() + timeout
    run = None
    while time.monotonic() < deadline:
        run = api.get(f"/runs/{rid}", headers=S["op"]).json()
        if run["status"] in FINISHED:
            return run
        time.sleep(2)
    pytest.fail(f"прогон {rid} не завершился за {timeout} с: {run}")


def wait_feed(api, source: str, timeout: float = 300) -> dict:
    deadline = time.monotonic() + timeout
    feed = None
    while time.monotonic() < deadline:
        feed = next(f for f in api.get("/feeds", headers=S["admin"]).json()
                    if f["source"] == source)
        if not feed["running"]:
            return feed
        time.sleep(1)
    pytest.fail(f"справочник {source} не загрузился за {timeout} с: {feed}")


def start(api, body: dict) -> int:
    # «normal»: на «бережном» профиле nmap -sV по молчащему порту идёт минутами
    body = {"rate_profile": "normal", **body}
    r = api.post(f"/engagements/{S['eid']}/runs", headers=S["op"], json=body)
    assert r.status_code == 202, r.text
    return r.json()["id"]


def coverage(api, rid: int) -> dict:
    r = api.get(f"/runs/{rid}/coverage", headers=S["op"])
    assert r.status_code == 200, r.text
    return r.json()


def entry(cov: dict, host: str, module: str) -> dict:
    return next(e for e in cov["entries"] if e["host"] == host and e["module"] == module)


def findings(api, rid: int, **params) -> list[dict]:
    r = api.get(f"/runs/{rid}/findings", headers=S["op"],
                params={"limit": 500, "include_info": True, **params})
    assert r.status_code == 200, r.text
    return r.json()


def report(api, rid: int, fmt: str = "html", **params) -> bytes:
    r = api.get(f"/runs/{rid}/report", headers=S["op"], params={"format": fmt, **params})
    assert r.status_code == 200, r.text[:500]
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / f"reliability-run{rid}.{fmt}").write_bytes(r.content)
    return r.content


# ---------- подготовка ----------
def test_r00_setup(api):
    S["admin"] = token(api, os.environ["SCANNER_E2E_USER"], os.environ["SCANNER_E2E_PASSWORD"])
    pw = os.environ["SCANNER_E2E_OP_PASSWORD"]
    r = api.post("/users", headers=S["admin"], json={
        "username": CRED_USER, "password": pw, "roles": ["operator", "host_credentials"]})
    assert r.status_code in (201, 409), r.text
    S["op"] = token(api, CRED_USER, pw)
    r = api.post("/engagements", headers=S["admin"],
                 json={"name": "e2e достоверность", "client": "стенд", "contract_ref": "E2E-R"})
    assert r.status_code == 201, r.text
    S["eid"] = r.json()["id"]
    for ip in (SSH13, SILENT, DOWN):
        r = api.post(f"/engagements/{S['eid']}/allowlist", headers=S["admin"],
                     json={"cidr": f"{ip}/32", "note": "стенд e2e"})
        assert r.status_code == 201, r.text
    r = api.post(f"/engagements/{S['eid']}/credentials", headers=S["op"], json={
        "name": "audit стенда", "username": "audit", "auth": "password",
        "password": SSH_PASSWORD, "port": SSH_PORT, "targets": [SSH13],
        "become": "none"})
    assert r.status_code == 201, r.text
    S["cred"] = r.json()["id"]
    r = api.post(f"/engagements/{S['eid']}/credentials", headers=S["op"], json={
        "name": "audit, SSH молчит", "username": "audit", "auth": "password",
        "password": SSH_PASSWORD, "port": SILENT_PORT, "targets": [SILENT],
        "become": "none"})
    assert r.status_code == 201, r.text
    S["cred_silent"] = r.json()["id"]


# ---------- 1. выключенный хост ----------
def test_r01_down_host_is_not_checked(api):
    rid = start(api, {"targets": [DOWN], "modules": ["discovery", "vuln"],
                      "vuln_engine": "nuclei", "name": "e2e: выключенный хост"})
    run = wait_run(api, rid)
    assert run["status"] == "failed", run
    assert run["error_message"].startswith(MSG_DOWN), run
    assert "-Pn" in run["error_message"]
    cov = coverage(api, rid)
    assert cov["summary"]["hosts_unreachable"] == 1 and cov["summary"]["hosts_checked"] == 0
    assert entry(cov, DOWN, "discovery")["status"] == "unreachable"
    summary = api.get(f"/runs/{rid}/findings/summary", headers=S["op"]).json()
    assert summary["coverage"]["hosts_unreachable"] == 1
    html = report(api, rid).decode()
    assert "Полнота проверки" in html and MSG_DOWN in html
    assert "не выявлено" not in html.lower()
    body = json.loads(report(api, rid, "json"))
    assert body["summary"]["risk_label"] == "Не оценён"
    S["down_run"] = rid


def test_r02_no_ping_option_is_kept_and_explained(api):
    plan = api.post(f"/engagements/{S['eid']}/runs/plan", headers=S["op"], json={
        "targets": [DOWN], "modules": ["discovery"], "no_ping": True}).json()
    assert any("-Pn" in w for w in plan["warnings"]), plan
    rid = start(api, {"targets": [DOWN], "modules": ["discovery"], "no_ping": True,
                      "name": "e2e: без ping"})
    run = wait_run(api, rid)
    assert run["options"].get("no_ping") is True
    assert run["status"] == "failed", run        # открытых портов нет — не «чисто»
    assert "-Pn" in entry(coverage(api, rid), DOWN, "discovery")["reason"]


# ---------- 2. SSH timeout ----------
def test_r03_ssh_timeout_is_partial(api):
    rid = start(api, {"targets": [SILENT], "modules": ["discovery"], "vuln_engine": "both",
                      "credential_ids": [S["cred_silent"]], "name": "e2e: SSH молчит"})
    run = wait_run(api, rid)
    assert run["status"] == "partial", run
    assert "таймаут" in run["error_message"].lower(), run
    cov = coverage(api, rid)
    assert entry(cov, SILENT, "discovery")["status"] == "completed"
    auth = entry(cov, SILENT, "auth_inventory")
    assert auth["status"] == "timeout", auth
    assert "попыт" in (auth["reason"] or ""), auth          # повтор был
    # WinRM-модуль без WinRM-учётки не запускался вовсе
    assert "win_inventory" not in run["modules"]
    titles = [f["title"] for f in findings(api, rid)]
    assert any("пакеты не проверены" in t for t in titles), titles
    html = report(api, rid).decode()
    assert "Полнота проверки" in html and "Таймаут" in html
    S["silent_run"] = rid


# ---------- 3/4. Debian 13 по SSH ----------
def test_r04_full_linux_profile_plan(api):
    profiles = {p["id"]: p for p in api.get("/run-profiles", headers=S["op"]).json()}
    assert {"linux_full", "windows_full", "network", "discovery"} <= set(profiles)
    plan = api.post(f"/engagements/{S['eid']}/runs/plan", headers=S["op"], json={
        "targets": [SSH13], "modules": ["discovery"], "profile": "linux_full",
        "credential_ids": [S["cred"]]}).json()
    names = [m["name"] for m in plan["modules"]]
    assert {"discovery", "vuln", "auth_inventory", "config_audit"} <= set(names), plan
    assert "win_inventory" not in names and plan["full_check"] is True, plan


def test_r05_debian13_without_bulletins_warns(api):
    rid = start(api, {"targets": [SSH13], "modules": ["discovery", "vuln", "auth_inventory"],
                      "credential_ids": [S["cred"]], "profile": "linux_full",
                      "name": "e2e: Debian 13 без бюллетеней"})
    run = wait_run(api, rid)
    assert run["status"] in ("done", "partial"), run
    cov = coverage(api, rid)
    assert entry(cov, SSH13, "auth_inventory")["status"] == "completed", cov
    pk = api.get(f"/runs/{rid}/packages", headers=S["op"], params={"host": SSH13}).json()
    ssh = next(p for p in pk if p["name"] == SSH_PKG)
    S["openssh"] = ssh["version"]
    w = [x for x in run["warnings"] if x["kind"] == "advisories_missing"]
    assert w and w[0]["family"] == FAMILY and w[0]["release"] == RELEASE, run["warnings"]
    assert "Бэкпорты не учтены" in w[0]["message"] and w[0]["loadable"] is True
    assert "Бэкпорты не учтены" in report(api, rid).decode()
    ready = api.get("/feeds/readiness", headers=S["admin"]).json()
    miss = next(r for r in ready["missing_releases"] if r["release"] == RELEASE)
    assert miss["family"] == FAMILY and SSH13 in miss["hosts"]
    S["deb_run1"] = rid


def _bulletin(installed: str) -> tuple[str, str]:
    """Бюллетень вендора для стенда: CVE-2099-0101 исправлена (бэкпортом) ровно в
    установленной версии пакета, CVE-2099-0102 — в следующей, ещё не установленной."""
    if FAMILY == "debian":
        epoch, _, rest = installed.rpartition(":")
        nxt = f"{epoch + ':' if epoch else ''}{rest}+e2e1"
        data = {"openssh": {
            "CVE-2099-0101": {"releases": {RELEASE: {"status": "resolved",
                                                     "fixed_version": installed}}},
            "CVE-2099-0102": {"releases": {RELEASE: {"status": "resolved",
                                                     "fixed_version": nxt}}}}}
        return f"debian-{RELEASE}.json", json.dumps(data)
    ver, _, rel = installed.rpartition("-r")
    # Инвентаризация apk не знает исходного пакета (origin) — бюллетень по имени
    # установленного пакета.
    data = {"distroversion": f"v{RELEASE}", "packages": [{"pkg": {
        "name": SSH_PKG, "secfixes": {installed: ["CVE-2099-0101"],
                                        f"{ver}-r{int(rel) + 1}": ["CVE-2099-0102"]}}}]}
    return f"alpine-{RELEASE}.json", json.dumps(data)


def test_r06_load_release_bulletins_in_one_action(api):
    ADVISORY_DIR.mkdir(parents=True, exist_ok=True)
    name, content = _bulletin(S["openssh"])
    (ADVISORY_DIR / name).write_text(content)
    body = {"family": FAMILY, "release": RELEASE}
    r = api.post("/feeds/advisories/releases", headers=S["op"], json=body)
    assert r.status_code == 403                      # нужно право управления
    for _ in range(2):                               # 7: повторная загрузка — без дублей
        r = api.post("/feeds/advisories/releases", headers=S["admin"], json=body)
        assert r.status_code == 202, r.text
        feed = wait_feed(api, "advisories")
        assert feed["last_result"] == "ok", feed
        assert f"{FAMILY}:{RELEASE} — 2" in feed["message"], feed
    ready = api.get("/feeds/readiness", headers=S["admin"]).json()
    rel = next(x for x in ready["releases"] if x["release"] == RELEASE)
    assert rel["records"] == 2
    assert not [x for x in ready["missing_releases"] if x["release"] == RELEASE]


def test_r07_backport_fixed_cve_not_active(api):
    rid = start(api, {"targets": [SSH13], "modules": ["discovery", "vuln", "auth_inventory"],
                      "credential_ids": [S["cred"]], "name": "e2e: Debian 13 с бюллетенями"})
    run = wait_run(api, rid)
    assert run["status"] in ("done", "partial"), run
    assert not [x for x in run["warnings"] if x["kind"] == "advisories_missing"], run
    found = {f["vuln_id"]: f for f in findings(api, rid)}
    assert "CVE-2099-0101" not in found              # исправлено бэкпортом
    f = found["CVE-2099-0102"]                       # исправление ещё не установлено
    assert f["source"] == "vendor_advisory" and f["confidence"] == "high", f
    S["deb_run2"] = rid


# ---------- 6. сравнение прогонов ----------
def test_r08_no_false_fixed_or_regression_across_different_hosts(api):
    # базовый для прогона по «молчащему» хосту — не прогон по Debian 13
    rid = start(api, {"targets": [SILENT], "modules": ["discovery"], "vuln_engine": "both",
                      "credential_ids": [S["cred_silent"]], "name": "e2e: SSH молчит, повтор"})
    wait_run(api, rid)
    s = api.get(f"/runs/{rid}/findings/summary", headers=S["op"]).json()
    assert s["previous_run_id"] == S["silent_run"], s
    assert s["regression"] == 0
    # явное сравнение с прогоном по другому хосту: несопоставимо, без «устранено»
    html = report(api, rid, compare_to=S["deb_run2"]).decode()
    assert "несопоставимы" in html.lower(), "нет предупреждения о несопоставимых прогонах"
