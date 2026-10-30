"""Уведомления (R9): маршрутизация, каналы на фейковых транспортах, повторы, дедуп Jira,
секреты, API и сквозной прогон → журнал доставки."""
from __future__ import annotations

import json
import smtplib
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from scanner.api.main import create_app
from scanner.api.settings import ApiSettings
from scanner.core.audit import DbAuditSink
from scanner.core.credentials import CredentialVault
from scanner.core.db import (
    AssetGroupRow,
    AssetRow,
    AuditLogRow,
    Engagement,
    IntegrationChannelRow,
    NotificationLogRow,
    ScanRun,
    asset_group_members,
)
from scanner.core.orchestrator import inline_executor
from scanner.feeds.scheduler import FeedScheduler, seed_feed_sync
from scanner.feeds.sources import FeedError, FeedSource
from scanner.integrations import dispatcher as disp
from scanner.integrations.base import (
    ChannelConfigError,
    DeliveryError,
    HttpResponse,
    Transports,
)
from scanner.integrations.channels import CHANNELS
from scanner.integrations.dispatcher import Dispatcher, scrub
from scanner.integrations.events import (
    FEED_STALE,
    NEW_CRITICAL,
    RUN_FINISHED,
    Event,
    Filters,
    HostInfo,
    Item,
    route,
)
from scanner.integrations.syslog_cef import cef_ext, cef_header
from scanner.reporting.remediation import RemediationResolver
from tests.test_api import (
    PASSWORD,
    SECRET,
    Api,
    FakeCred,
    FakeDiscovery,
    Recorder,
    _run,
)

VAULT = CredentialVault("v" * 32)
TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ-secret"
SMTP_PASSWORD = "smtp-p@ss-12345"
JIRA_TOKEN = "jira-api-token-98765"


# ---------- фейковые транспорты ----------
class FakeHttp:
    def __init__(self):
        self.calls: list[dict] = []
        self.responses: list[HttpResponse | Exception] = []
        self.issue_no = 0

    def request(self, method, url, *, headers=None, json=None, params=None, auth=None):
        self.calls.append({"method": method, "url": url, "headers": headers or {},
                           "json": json, "auth": auth})
        if self.responses:
            r = self.responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        if url.endswith("/sendMessage"):
            return HttpResponse(200, {"ok": True})
        if url.endswith("/rest/api/2/issue"):
            self.issue_no += 1
            return HttpResponse(201, {"key": f"SEC-{self.issue_no}"})
        if url.endswith("/rest/api/2/myself"):
            return HttpResponse(200, {"displayName": "Scanner Bot"})
        return HttpResponse(404, "")


class FakeSmtp:
    sent: ClassVar[list] = []
    logins: ClassVar[list] = []
    fail: ClassVar[Exception | None] = None

    def __init__(self, host, port, use_ssl, timeout):
        self.host, self.port, self.use_ssl, self.started = host, port, use_ssl, False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.started = True

    def login(self, user, password):
        FakeSmtp.logins.append((user, password))

    def send_message(self, msg):
        if FakeSmtp.fail:
            raise FakeSmtp.fail
        FakeSmtp.sent.append((self.host, self.port, self.started, msg))


@pytest.fixture(autouse=True)
def _reset_smtp():
    FakeSmtp.sent, FakeSmtp.logins, FakeSmtp.fail = [], [], None


@pytest.fixture(autouse=True)
def _seed(sqlite_factory):
    """Договор №1 и прогон №7 из _event(): в журнале доставки на них внешние ключи."""
    with sqlite_factory.begin() as s:
        s.add(Engagement(id=1, name="ООО Ромашка"))
        s.flush()
        s.add(ScanRun(id=7, engagement_id=1, modules=["vuln"], status="done"))


@pytest.fixture
def http():
    return FakeHttp()


@pytest.fixture
def syslog():
    return []


@pytest.fixture
def tx(http, syslog):
    return Transports(http=http, smtp_factory=FakeSmtp,
                      syslog_send=lambda h, p, proto, data: syslog.append((h, p, proto, data)),
                      hostname="scanner-host")


@pytest.fixture
def dispatcher(sqlite_factory, tx):
    return Dispatcher(sqlite_factory, DbAuditSink(sqlite_factory), vault=VAULT,
                      public_url="https://scan.example.local", transports=tx,
                      executor=inline_executor(), tick_seconds=0)


def _channel(factory, kind, config, *, secrets=None, events=None, filters=None,
             enabled=True, name=None) -> int:
    impl = CHANNELS[kind]
    with factory.begin() as s:
        row = IntegrationChannelRow(
            name=name or kind, type=kind, enabled=enabled, config=impl.validate(config),
            secret_enc=VAULT.encrypt(secrets) if secrets else None,
            events=events or sorted(impl.supported_events), filters=filters or {})
        s.add(row)
        s.flush()
        return row.id


SMTP_CFG = {"host": "mail.local", "sender": "scanner@corp.local", "to": ["sec@corp.local"],
            "username": "scanner"}
TG_CFG = {"chat_id": "-100123"}
SYSLOG_CFG = {"host": "siem.local", "protocol": "tcp"}
JIRA_CFG = {"base_url": "https://jira.corp.local", "project_key": "sec",
            "username": "bot@corp.local"}


def _item(key="k1", host="10.0.0.5", sev="critical", status="new", prio="critical",
          owner=None, groups=(), **kw) -> Item:
    return Item(dedup_key=key, host=host, port=22, title=f"CVE-2024-0001 in {host}",
                severity=sev, status=status, vuln_id="CVE-2024-0001", priority=prio,
                score=97.5, rank=1, owner=owner, groups=list(groups),
                bdu_ids=["BDU:2024-00001"], **kw)


def _event(items, kind=NEW_CRITICAL, hosts=None) -> Event:
    return Event(kind=kind, title="Прогон", engagement_id=1, engagement_name="ООО Ромашка",
                 scan_run_id=7, run_name="Обнаружение + Nuclei", run_status="done",
                 link="https://scan.example.local/runs/7",
                 hosts=hosts or [HostInfo(i.host, i.owner, i.groups) for i in items],
                 items=items)


def _logs(factory) -> list[NotificationLogRow]:
    with factory() as s:
        rows = list(s.scalars(select(NotificationLogRow).order_by(NotificationLogRow.id)))
        s.expunge_all()
        return rows


# ---------- маршрутизация ----------
def test_route_by_subscription_and_thresholds():
    ev = _event([_item("a"), _item("b", sev="high", prio="high"),
                 _item("c", status="open"), _item("d", sev="high", prio="critical")])
    only_run = route(ev, [RUN_FINISHED], Filters())
    assert only_run is None                                   # не подписан на new_critical
    default = route(ev, [NEW_CRITICAL], Filters())
    assert {i.dedup_key for i in default.items} == {"a", "d"}   # критичные; open и high — нет
    high = route(ev, [NEW_CRITICAL], Filters(min_severity="high"))
    assert {i.dedup_key for i in high.items} == {"a", "b", "d"}
    both = route(ev, [NEW_CRITICAL], Filters(min_severity="critical", min_priority="critical"))
    assert {i.dedup_key for i in both.items} == {"a"}
    assert route(_event([_item(status="open")]), [NEW_CRITICAL], Filters()) is None


def test_route_by_groups_owners_and_engagement():
    ev = _event([_item("a", "10.0.0.1", owner="Иванов", groups=["DMZ"]),
                 _item("b", "10.0.0.2", owner="Петров", groups=["Офис"]),
                 _item("c", "10.0.0.3")])
    dmz = route(ev, [NEW_CRITICAL], Filters(groups=["dmz"]))          # регистр не важен
    assert [i.dedup_key for i in dmz.items] == ["a"]
    own = route(ev, [NEW_CRITICAL], Filters(owners=["Петров"]))
    assert [i.dedup_key for i in own.items] == ["b"]
    both = route(ev, [NEW_CRITICAL], Filters(groups=["DMZ"], owners=["Петров"]))
    assert {i.dedup_key for i in both.items} == {"a", "b"}
    assert route(ev, [NEW_CRITICAL], Filters(groups=["Серверная"])) is None
    assert route(ev, [NEW_CRITICAL], Filters(engagements=[2])) is None
    assert route(ev, [NEW_CRITICAL], Filters(engagements=[1])) is not None
    # сводка прогона по группе: только её хосты
    run = route(_event(ev.items, kind=RUN_FINISHED), [RUN_FINISHED], Filters(groups=["DMZ"]))
    assert run.hosts_total == 1 and [i.dedup_key for i in run.items] == ["a"]


def test_feed_event_ignores_asset_filters():
    ev = Event(kind=FEED_STALE, title="NVD", message="x", source="nvd")
    assert route(ev, [FEED_STALE], Filters(groups=["DMZ"], engagements=[5])) is ev


# ---------- валидация каналов ----------
def test_channel_validation():
    smtp = CHANNELS["smtp"]
    assert smtp.validate(SMTP_CFG)["port"] == 587                       # STARTTLS по умолчанию
    with pytest.raises(ChannelConfigError, match="без шифрования"):
        smtp.validate({**SMTP_CFG, "security": "none"})                 # логин без TLS
    with pytest.raises(ChannelConfigError):
        smtp.validate({**SMTP_CFG, "to": ["не-почта"]})
    with pytest.raises(ChannelConfigError):
        smtp.validate_secrets({}, smtp.validate(SMTP_CFG))              # логин без пароля
    tg = CHANNELS["telegram"]
    assert tg.validate(TG_CFG)["api_base"] == "https://api.telegram.org"
    with pytest.raises(ChannelConfigError):
        tg.validate({"chat_id": "abc def"})
    with pytest.raises(ChannelConfigError):
        tg.validate_secrets({"bot_token": "плохой токен"}, {})
    with pytest.raises(ChannelConfigError):
        tg.validate({**TG_CFG, "api_base": "ftp://x"})
    with pytest.raises(ChannelConfigError):
        CHANNELS["syslog_cef"].validate({"host": "x", "facility": "kern"})
    j = CHANNELS["jira"]
    assert j.validate(JIRA_CFG)["project_key"] == "SEC"
    with pytest.raises(ChannelConfigError):
        j.validate({**JIRA_CFG, "base_url": "https://u:p@jira"})        # логин в URL
    with pytest.raises(ChannelConfigError):
        j.validate({**JIRA_CFG, "username": ""})


# ---------- каналы ----------
def test_smtp_channel_sends_summary_without_secrets(sqlite_factory, dispatcher):
    _channel(sqlite_factory, "smtp", SMTP_CFG, secrets={"password": SMTP_PASSWORD})
    dispatcher.emit(_event([_item()]))
    (host, port, starttls, msg), = FakeSmtp.sent
    assert (host, port, starttls) == ("mail.local", 587, True)
    assert FakeSmtp.logins == [("scanner", SMTP_PASSWORD)]
    body = msg.get_content()
    assert "10.0.0.5:22" in body and "https://scan.example.local/runs/7" in body
    assert "BDU:2024-00001" in body and SMTP_PASSWORD not in body + str(msg)
    assert msg["To"] == "sec@corp.local" and "Scanner" in msg["Subject"]


def test_telegram_channel_posts_to_bot_api(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    dispatcher.emit(_event([_item()]))
    call, = http.calls
    assert call["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert call["json"]["chat_id"] == "-100123" and "10.0.0.5:22" in call["json"]["text"]
    assert _logs(sqlite_factory)[0].status == "sent"


def test_syslog_cef_format_and_escaping(sqlite_factory, dispatcher, syslog):
    _channel(sqlite_factory, "syslog_cef", SYSLOG_CFG)
    dispatcher.emit(_event([_item(), _item("k2", "10.0.0.6")]))
    assert len(syslog) == 2
    host, port, proto, data = syslog[0]
    assert (host, port, proto) == ("siem.local", 514, "tcp") and data.endswith(b"\n")
    line = data.decode().strip()
    assert line.startswith("<162>1 ")                       # local4 (20)*8 + crit (2)
    assert " scanner-host scanner - new_critical - CEF:0|Scanner|Scanner|1.0|new_critical|" in line
    assert "|10|" in line and "src=10.0.0.5" in line and "dpt=22" in line
    assert "cs1=CVE-2024-0001" in line and "cs2=BDU:2024-00001" in line
    assert cef_header("a|b\\c") == "a\\|b\\\\c"
    assert cef_ext("k=v\nline") == "k\\=v\\nline"


def test_syslog_udp_has_no_newline(sqlite_factory, dispatcher, syslog):
    _channel(sqlite_factory, "syslog_cef", {**SYSLOG_CFG, "protocol": "udp"},
             events=[RUN_FINISHED])
    dispatcher.emit(_event([_item()], kind=RUN_FINISHED))
    assert syslog and not syslog[0][3].endswith(b"\n") and b"run_finished" in syslog[0][3]


def test_run_finished_summary_text(sqlite_factory, dispatcher):
    _channel(sqlite_factory, "smtp", {**SMTP_CFG, "username": ""}, events=[RUN_FINISHED])
    ev = _event([_item(), _item("o", status="open", sev="medium", prio="medium")],
                kind=RUN_FINISHED)
    ev.fixed_total = 3
    dispatcher.emit(ev)
    body = FakeSmtp.sent[0][3].get_content()
    assert "Хостов: 2; находок: 2" in body and "Новых: 1; устранено: 3" in body


# ---------- повторы, журнал, аудит ----------
def test_retry_with_backoff_then_success(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    http.responses = [HttpResponse(502, ""), HttpResponse(200, {"ok": True})]
    dispatcher.emit(_event([_item()]))
    row, = _logs(sqlite_factory)
    assert (row.status, row.attempts) == ("retry", 1) and "502" in row.last_error
    nxt = row.next_attempt_at.replace(tzinfo=UTC)
    assert timedelta(seconds=30) < nxt - datetime.now(UTC) <= timedelta(seconds=61)
    # раньше срока — не отправляется
    assert dispatcher.tick() == 0
    assert dispatcher.tick(datetime.now(UTC) + timedelta(minutes=2)) == 1
    row, = _logs(sqlite_factory)
    assert (row.status, row.attempts, row.last_error) == ("sent", 2, None)
    assert row.sent_at is not None
    with sqlite_factory() as s:
        results = [r for r in s.scalars(select(AuditLogRow.result).where(
            AuditLogRow.action == "notification"))]
    assert results == ["retry", "sent"]


def test_failed_after_max_attempts_and_manual_retry(sqlite_factory, dispatcher, http):
    cid = _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    http.responses = [HttpResponse(500, "")] * disp.MAX_ATTEMPTS
    dispatcher.emit(_event([_item()]))
    far = datetime.now(UTC)
    for _ in range(disp.MAX_ATTEMPTS):
        far += timedelta(hours=2)
        dispatcher.tick(far)
    row, = _logs(sqlite_factory)
    assert (row.status, row.attempts) == ("failed", disp.MAX_ATTEMPTS)
    assert dispatcher.tick(far + timedelta(days=1)) == 0           # больше не пытаемся
    assert dispatcher.retry(row.id) == "sent"                      # вручную — получилось
    assert cid


def test_permanent_error_is_not_retried(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    http.responses = [HttpResponse(400, {"ok": False, "description": "chat not found"})]
    dispatcher.emit(_event([_item()]))
    row, = _logs(sqlite_factory)
    assert (row.status, row.attempts) == ("failed", 1) and "chat not found" in row.last_error


def test_smtp_errors_classified(sqlite_factory, dispatcher):
    _channel(sqlite_factory, "smtp", {**SMTP_CFG, "username": ""})
    FakeSmtp.fail = smtplib.SMTPRecipientsRefused({})
    dispatcher.emit(_event([_item()]))
    assert _logs(sqlite_factory)[0].status == "failed"
    FakeSmtp.fail = smtplib.SMTPServerDisconnected("down")
    dispatcher.emit(_event([_item("k2")]))
    assert _logs(sqlite_factory)[1].status == "retry"


def test_secrets_never_reach_log_or_audit(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    http.responses = [DeliveryError(f"boom {TOKEN} boom"), RuntimeError(f"x {TOKEN}")]
    dispatcher.emit(_event([_item()]))
    dispatcher.tick(datetime.now(UTC) + timedelta(hours=1))
    dump = json.dumps([(r.last_error, r.payload) for r in _logs(sqlite_factory)])
    with sqlite_factory() as s:
        dump += json.dumps([a for a in s.scalars(select(AuditLogRow.details))], default=str)
    assert TOKEN not in dump and "***" in dump
    assert scrub(f"a {TOKEN} b", {"bot_token": TOKEN}) == "a *** b"


def test_no_vault_fails_without_leak(sqlite_factory, tx):
    d = Dispatcher(sqlite_factory, DbAuditSink(sqlite_factory), vault=None, transports=tx,
                   executor=inline_executor(), tick_seconds=0)
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN})
    d.emit(_event([_item()]))
    row, = _logs(sqlite_factory)
    assert row.status == "failed" and "ключ шифрования" in row.last_error


def test_disabled_channel_gets_nothing(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN}, enabled=False)
    assert dispatcher.emit(_event([_item()])) == [] and not http.calls


def test_channel_filter_applies_per_channel(sqlite_factory, dispatcher, http, syslog):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN},
             filters={"groups": ["DMZ"]})
    _channel(sqlite_factory, "syslog_cef", SYSLOG_CFG)
    dispatcher.emit(_event([_item("a", "10.0.0.1", groups=["DMZ"]),
                            _item("b", "10.0.0.2", groups=["Офис"])]))
    assert len(http.calls) == 1 and "10.0.0.1" in http.calls[0]["json"]["text"]
    assert "10.0.0.2" not in http.calls[0]["json"]["text"]
    assert len(syslog) == 2


# ---------- Jira ----------
def test_jira_creates_one_issue_per_finding_and_dedups(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "jira", {**JIRA_CFG, "labels": "pentest"},
             secrets={"api_token": JIRA_TOKEN})
    ev = _event([_item("a"), _item("b", "10.0.0.6")])
    dispatcher.emit(ev)
    posts = [c for c in http.calls if c["method"] == "POST"]
    assert len(posts) == 2 and posts[0]["auth"] == ("bot@corp.local", JIRA_TOKEN)
    f = posts[0]["json"]["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Task"}
    assert "pentest" in f["labels"] and any(x.startswith("scanner-") for x in f["labels"])
    assert "https://scan.example.local/runs/7" in f["description"]
    assert [r.external_ref for r in _logs(sqlite_factory)] == ["SEC-1", "SEC-2"]
    # тот же ключ находки в следующем прогоне и повторная эмиссия — дублей нет
    dispatcher.emit(ev)
    dispatcher.emit(_event([_item("a")]))
    assert len([c for c in http.calls if c["method"] == "POST"]) == 2
    assert len(_logs(sqlite_factory)) == 2
    # новая находка — новая задача
    dispatcher.emit(_event([_item("c", "10.0.0.7")]))
    assert len([c for c in http.calls if c["method"] == "POST"]) == 3


def test_jira_retry_does_not_duplicate_other_issues(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "jira", JIRA_CFG, secrets={"api_token": JIRA_TOKEN})
    http.responses = [HttpResponse(201, {"key": "SEC-1"}), HttpResponse(503, "")]
    dispatcher.emit(_event([_item("a"), _item("b", "10.0.0.6")]))
    assert [r.status for r in _logs(sqlite_factory)] == ["sent", "retry"]
    dispatcher.tick(datetime.now(UTC) + timedelta(hours=1))
    assert [r.status for r in _logs(sqlite_factory)] == ["sent", "sent"]
    assert len([c for c in http.calls if c["method"] == "POST"]) == 3    # 2 + 1 повтор


def test_jira_respects_max_issues_and_event_support(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "jira", {**JIRA_CFG, "max_issues": 2},
             secrets={"api_token": JIRA_TOKEN})
    dispatcher.emit(_event([_item(f"k{i}", f"10.0.1.{i}") for i in range(5)]))
    assert len(_logs(sqlite_factory)) == 2
    dispatcher.emit(_event([_item()], kind=RUN_FINISHED))               # Jira только new_critical
    assert len(_logs(sqlite_factory)) == 2


def test_jira_bearer_auth_header(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "jira", {**JIRA_CFG, "auth_type": "bearer", "username": ""},
             secrets={"api_token": JIRA_TOKEN})
    dispatcher.emit(_event([_item()]))
    c = http.calls[0]
    assert c["auth"] is None and c["headers"]["Authorization"] == f"Bearer {JIRA_TOKEN}"


# ---------- feed_stale ----------
def test_feed_stale_deduplicated_per_day(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN},
             events=[FEED_STALE])
    dispatcher.notify_feed_stale("nvd", "NVD (CVE)", "Обновление не удалось: таймаут")
    dispatcher.notify_feed_stale("nvd", "NVD (CVE)", "Обновление не удалось: таймаут")
    dispatcher.notify_feed_stale("bdu", "БДУ ФСТЭК", "нет файла")
    assert len(http.calls) == 2
    with sqlite_factory.begin() as s:
        s.execute(update(NotificationLogRow).values(
            created_at=datetime.now(UTC) - timedelta(days=2)))
    dispatcher.notify_feed_stale("nvd", "NVD (CVE)", "снова")
    assert len(http.calls) == 3


def test_feed_scheduler_error_notifies(sqlite_factory, dispatcher, http):
    _channel(sqlite_factory, "telegram", TG_CFG, secrets={"bot_token": TOKEN},
             events=[FEED_STALE])

    def broken(ctx):
        raise FeedError("NVD недоступен")

    sources = {"nvd": FeedSource("nvd", "NVD (CVE)", broken)}
    seed_feed_sync(sqlite_factory, timezone="UTC", sources=sources)
    sched = FeedScheduler(sqlite_factory, DbAuditSink(sqlite_factory), sources=sources,
                          executor=inline_executor(), tick_seconds=0,
                          notifier=dispatcher.notify_feed_stale)
    assert sched.execute("nvd", datetime.now(UTC), "test") == "error"
    assert "NVD недоступен" in http.calls[0]["json"]["text"]


# ---------- API ----------
@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def api(sqlite_factory, rec, tx):
    from tests.test_api import FakeVuln
    registry = {"discovery": lambda: FakeDiscovery(rec),
                "vuln": lambda: FakeVuln(rec, ["CVE-2016-6210"]),
                "cred_audit": lambda: FakeCred(rec)}
    settings = ApiSettings(secret=SECRET, bootstrap_admin="root",
                           bootstrap_password=PASSWORD, public_url="https://scan.local",
                           notify_tick_seconds=0)
    app = create_app(session_factory=sqlite_factory, settings=settings, registry=registry,
                     executor=inline_executor(), notify_transports=tx,
                     notify_executor=inline_executor(),
                     resolver_factory=lambda f: RemediationResolver())
    with TestClient(app) as c:
        yield Api(c)


def _create(api, **kw):
    body = {"name": "Telegram SOC", "type": "telegram", "config": TG_CFG,
            "secrets": {"bot_token": TOKEN}, **kw}
    return api.c.post("/integrations/channels", headers=api.admin, json=body)


def test_api_channel_lifecycle_hides_secrets(api, sqlite_factory):
    r = _create(api, events=["new_critical"], filters={"min_severity": "high",
                                                       "groups": ["DMZ"]})
    assert r.status_code == 201, r.text
    ch = r.json()
    assert ch["has_secret"] is True and TOKEN not in r.text and "secrets" not in ch
    assert ch["filters"]["groups"] == ["DMZ"] and ch["events"] == ["new_critical"]
    listing = api.c.get("/integrations/channels", headers=api.admin)
    assert TOKEN not in listing.text and listing.json()[0]["id"] == ch["id"]
    # токен в БД — только шифртекстом
    with sqlite_factory() as s:
        row = s.get(IntegrationChannelRow, ch["id"])
        assert TOKEN not in row.secret_enc and VAULT.__class__ and row.secret_enc
    # изменение без секретов не трогает токен; со своим — заменяет
    p = api.c.patch(f"/integrations/channels/{ch['id']}", headers=api.admin,
                    json={"name": "SOC", "enabled": False})
    assert p.status_code == 200 and p.json()["has_secret"] and not p.json()["enabled"]
    assert api.c.delete(f"/integrations/channels/{ch['id']}",
                        headers=api.admin).status_code == 204
    audit = json.dumps(api.audit(sqlite_factory))
    with sqlite_factory() as s:
        audit += json.dumps([a for a in s.scalars(select(AuditLogRow.details))], default=str)
    assert TOKEN not in audit
    assert {"channel_create", "channel_update", "channel_delete"} <= {
        a[1] for a in api.audit(sqlite_factory)}


def test_api_rbac_and_validation(api):
    aud = api.user("aud", "auditor")
    op = api.user("op", "operator")
    assert _create(api).status_code == 201
    for who in (aud, op):                                  # без manage_engagements
        r = api.c.post("/integrations/channels", headers=who,
                       json={"name": "x", "type": "telegram", "config": TG_CFG,
                             "secrets": {"bot_token": TOKEN}})
        assert r.status_code == 403
        assert api.c.post("/integrations/channels/1/test", headers=who).status_code == 403
        assert api.c.delete("/integrations/channels/1", headers=who).status_code == 403
    assert api.c.get("/integrations/channels", headers=aud).status_code == 200   # просмотр
    assert api.c.get("/integrations/channels").status_code == 401
    bad = [
        {"type": "carrier-pigeon", "config": {}},
        {"type": "telegram", "config": {"chat_id": "??"}, "secrets": {"bot_token": TOKEN}},
        {"type": "telegram", "config": TG_CFG, "secrets": {}},                 # нет токена
        {"type": "jira", "config": JIRA_CFG, "secrets": {"api_token": JIRA_TOKEN},
         "events": ["run_finished"]},                                            # Jira: только new_critical
        {"type": "telegram", "config": TG_CFG, "secrets": {"bot_token": TOKEN},
         "filters": {"min_severity": "ужасный"}},
        {"type": "telegram", "config": TG_CFG, "secrets": {"bot_token": TOKEN},
         "events": ["nope"]},
    ]
    for b in bad:
        r = api.c.post("/integrations/channels", headers=api.admin, json={"name": "x", **b})
        assert r.status_code == 422, (b, r.text)


def test_api_test_send_and_log(api, http):
    cid = _create(api).json()["id"]
    r = api.c.post(f"/integrations/channels/{cid}/test", headers=api.admin)
    assert r.status_code == 200 and r.json()["status"] == "sent" and r.json()["event"] == "test"
    assert "Тестовое" in http.calls[0]["json"]["text"]
    http.responses = [HttpResponse(401, {"ok": False, "description": "Unauthorized"})]
    r = api.c.post(f"/integrations/channels/{cid}/test", headers=api.admin)
    assert r.json()["status"] == "failed" and "401" in r.json()["last_error"]
    log = api.c.get("/integrations/log", headers=api.admin, params={"status": "failed"})
    assert [x["status"] for x in log.json()] == ["failed"] and TOKEN not in log.text
    rid = log.json()[0]["id"]
    assert api.c.post(f"/integrations/log/{rid}/retry", headers=api.admin).json()["status"] == "sent"
    assert api.c.post(f"/integrations/log/{rid}/retry", headers=api.admin).status_code == 404


def test_api_jira_test_checks_login_without_creating_issue(api, http):
    r = api.c.post("/integrations/channels", headers=api.admin, json={
        "name": "Jira", "type": "jira", "config": JIRA_CFG, "secrets": {"api_token": JIRA_TOKEN},
        "events": ["new_critical"]})
    cid = r.json()["id"]
    assert api.c.post(f"/integrations/channels/{cid}/test",
                      headers=api.admin).json()["status"] == "sent"
    assert [c["url"] for c in http.calls] == ["https://jira.corp.local/rest/api/2/myself"]


def test_run_end_to_end_notifies_with_groups_and_priority(api, sqlite_factory, http, syslog):
    eid = api.engagement("10.0.0.0/24")
    with sqlite_factory.begin() as s:                # актив с группой и критичностью (R7)
        a = AssetRow(engagement_id=eid, address="10.0.0.5", owner="Иванов",
                     criticality="critical")
        g = AssetGroupRow(engagement_id=eid, name="DMZ")
        s.add_all([a, g])
        s.flush()
        s.execute(asset_group_members.insert().values(asset_id=a.id, group_id=g.id))
    _create(api, name="DMZ-alerts", events=["run_finished", "new_critical"],
            filters={"groups": ["DMZ"], "min_priority": "high"})
    api.c.post("/integrations/channels", headers=api.admin, json={
        "name": "SIEM", "type": "syslog_cef", "config": SYSLOG_CFG, "events": ["run_finished"]})
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.5", "10.0.0.6"])
    assert r.status_code == 202, r.text
    texts = [c["json"]["text"] for c in http.calls]
    # run_finished со сводкой и ссылкой + new_critical (первый прогон: всё новое)
    assert any("Хостов: 1; находок: 2" in t for t in texts)         # сводка только по группе DMZ
    assert all("• 10.0.0.6" not in t for t in texts)            # хост вне группы DMZ
    crit = [t for t in texts if "Новые критичные" in t]
    assert crit and "10.0.0.5" in crit[0] and "CVE-2016-6210" in crit[0]
    assert "https://scan.local/runs/" in texts[0]
    assert len(syslog) == 1 and b"run_finished" in syslog[0][3]
    with sqlite_factory() as s:
        statuses = {x.status for x in s.scalars(select(NotificationLogRow))}
        assert statuses == {"sent"}
        evs = sorted(x.event for x in s.scalars(select(NotificationLogRow)))
    assert evs == ["new_critical", "run_finished", "run_finished"]
    # второй прогон: находки те же -> не «новые»; уведомление только о завершении
    http.calls.clear()
    assert _run(api, eid, op, ["10.0.0.5"]).status_code == 202
    assert all("Новые критичные" not in c["json"]["text"] for c in http.calls)


def test_notifier_failure_does_not_break_run(api, sqlite_factory, http):
    eid = api.engagement("10.0.0.0/24")
    api.c.app.state.runs.notifier = lambda run_id: 1 / 0
    op = api.user("op", "operator")
    r = _run(api, eid, op, ["10.0.0.5"])
    assert r.status_code == 202
    run = api.c.get(f"/runs/{r.json()['id']}", headers=api.admin).json()
    assert run["status"] == "done"
