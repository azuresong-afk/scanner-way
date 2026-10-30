"""Операционный CLI: загрузка справочников, запуск прогона, выгрузка отчёта.

    scanner feeds sync-bdu --file vullist.xlsx
    scanner feeds sync-nvd [--file nvdcve-2.0-2024.json.gz ...] [--since ... --until ...]
    scanner run --engagement 1 --targets 10.0.0.0/28 10.0.0.50 --modules discovery vuln \\
                --confirm-authorized
    scanner report --run 7 --format pdf [--out report.pdf] [--brief]
    scanner credentials add --engagement 1 --name "root на 10.0.0.0/24" --user audit \
                --key-file ~/.ssh/id_ed25519 [--targets 10.0.0.0/24]
    scanner run --engagement 1 --targets 10.0.0.0/24 --engine credentialed --credential 1 \
                --confirm-authorized --allow-credentials
    scanner run --engagement 1 --targets 10.0.0.0/24 --modules discovery config_audit \
                --credential 1 --confirm-authorized --allow-credentials

БД — `--db-url` / `SCANNER_DATABASE_URL`, иначе Postgres из настроек окружения.
Перед каждой командой схема поднимается миграциями Alembic (`alembic upgrade
head`); SQLite (офлайн-стенд, тесты) Alembic не поддерживает — для неё таблицы
создаются из ORM-метаданных.

Прогон идёт через `RunService`: allowlist договора читается из БД, цели вне
него отбрасываются и пишутся в аудит. CLI сам по себе не расширяет права:
договор и allowlist заводит admin (API), а запуск требует явного
подтверждения, что работы проводятся в рамках договора; модуль cred_audit —
отдельного флага, как и использование учётных записей активов
(`--allow-credentials`). Пароль учётки CLI не принимает в аргументах (он попал
бы в историю shell и в список процессов) — только из запроса или переменной
окружения. Все действия CLI пишутся в `audit_log` от имени `--actor`.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from sqlalchemy.engine import Engine

from scanner.core.orchestrator import CREDENTIAL_MODULES, MODULE_ORDER, VULN_ENGINES
from scanner.core.ratelimit import PROFILES

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
REPORT_FORMATS = ("html", "pdf", "docx", "json")
FINISHED = {"done", "failed", "stopped"}


class CliError(Exception):
    """Ошибка, о которой сообщаем пользователю без трейсбека."""


def _default_actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 — нет записи в passwd (контейнер)
        user = "unknown"
    return f"cli:{user}"


def _iso_dt(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"ожидается дата ISO 8601: {value}") from e
    return dt if dt.tzinfo else dt.astimezone()


# ========== Аргументы ==========
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Сканер уязвимостей (только авторизованные по договору цели).")
    p.add_argument("--db-url", default=os.environ.get("SCANNER_DATABASE_URL"),
                   help="URL БД SQLAlchemy (по умолчанию SCANNER_DATABASE_URL "
                        "или Postgres из настроек)")
    p.add_argument("--actor", default=_default_actor(),
                   help="субъект для журнала аудита (по умолчанию cli:<пользователь>)")
    p.add_argument("--no-migrate", action="store_true",
                   help="не применять миграции схемы перед командой")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    # --- feeds ---
    feeds = sub.add_parser("feeds", help="загрузка справочников уязвимостей")
    fsub = feeds.add_subparsers(dest="feed_command", required=True, metavar="feed_command")

    bdu = fsub.add_parser("sync-bdu", help="загрузить выгрузку БДУ ФСТЭК (XLSX)")
    bdu.add_argument("--file", required=True, type=Path,
                     help="XLSX-выгрузка БДУ (vullist.xlsx)")
    bdu.add_argument("--batch-size", type=int, default=1000)
    bdu.set_defaults(handler=cmd_sync_bdu)

    nvd = fsub.add_parser("sync-nvd", help="загрузить CVE из NVD (API 2.0 или офлайн-фиды)")
    nvd.add_argument("--file", dest="files", action="append", type=Path, default=[],
                     help="офлайн-фид NVD 2.0 (.json/.json.gz); можно несколько раз. "
                          "Без --file — выгрузка через API")
    nvd.add_argument("--api-key", default=None,
                     help="ключ NVD API (по умолчанию NVD_API_KEY)")
    nvd.add_argument("--cve", help="загрузить одну CVE через API")
    nvd.add_argument("--since", type=_iso_dt,
                     help="изменённые с этой даты (API, период не более 120 дней)")
    nvd.add_argument("--until", type=_iso_dt, help="изменённые по эту дату (с --since)")
    nvd.add_argument("--batch-size", type=int, default=1000)
    nvd.set_defaults(handler=cmd_sync_nvd)

    auto = fsub.add_parser("auto-enabled", help="включено ли автообновление источника "
                                                "по расписанию (код 0 — да, 1 — нет)")
    auto.add_argument("source", help="bdu | nvd | nuclei")
    auto.set_defaults(handler=cmd_auto_enabled)

    # --- run ---
    run = sub.add_parser("run", help="запустить прогон по договору (синхронно)")
    run.add_argument("--engagement", required=True, type=int, help="id договора")
    run.add_argument("--targets", required=True, nargs="+",
                     help="IP-адреса и подсети CIDR (только из allowlist договора)")
    run.add_argument("--modules", nargs="+", default=["discovery", "vuln"],
                     choices=MODULE_ORDER, help="модули (по умолчанию discovery vuln)")
    run.add_argument("--rate", default="gentle", choices=sorted(PROFILES),
                     help="профиль нагрузки (по умолчанию gentle)")
    run.add_argument("--confirm-authorized", action="store_true",
                     help="подтверждаю: работы по целям разрешены договором")
    run.add_argument("--allow-cred-audit", action="store_true",
                     help="подтверждаю: проверка учётных данных согласована с заказчиком")
    run.add_argument("--engine", choices=sorted(VULN_ENGINES),
                     help="движок поиска уязвимостей: nuclei — сетевые проверки, "
                          "credentialed — пакеты по учётной записи, both — оба "
                          "(заменяет vuln/auth_inventory в --modules)")
    run.add_argument("--credential", type=int, action="append", default=[],
                     dest="credentials", metavar="ID",
                     help="учётная запись актива для auth_inventory (можно несколько)")
    run.add_argument("--allow-credentials", action="store_true",
                     help="подтверждаю: вход на активы по учётным записям согласован "
                          "с заказчиком")
    run.add_argument("--name", help="имя прогона (по умолчанию — по модулям и целям)")
    run.set_defaults(handler=cmd_run)

    # --- credentials ---
    cred = sub.add_parser("credentials", help="учётные записи активов договора")
    csub = cred.add_subparsers(dest="credentials_command", required=True, metavar="action")
    cadd = csub.add_parser("add", help="завести учётку (SSH: пароль или ключ)")
    cadd.add_argument("--engagement", required=True, type=int, help="id договора")
    cadd.add_argument("--name", required=True, help="название учётки")
    cadd.add_argument("--user", required=True, dest="username", help="логин на активе")
    cadd.add_argument("--port", type=int, default=22, help="порт SSH (по умолчанию 22)")
    auth = cadd.add_mutually_exclusive_group(required=True)
    auth.add_argument("--key-file", type=Path, help="закрытый ключ SSH (OpenSSH/PEM)")
    auth.add_argument("--password-env", metavar="VAR",
                      help="взять пароль из переменной окружения VAR")
    auth.add_argument("--ask-password", action="store_true",
                      help="запросить пароль с терминала")
    cadd.add_argument("--passphrase-env", metavar="VAR",
                      help="парольная фраза ключа из переменной окружения VAR")
    cadd.add_argument("--targets", nargs="+", default=[],
                      help="область действия: IP/подсети из allowlist договора "
                           "(по умолчанию — все цели прогона)")
    cadd.add_argument("--become", choices=("sudo", "none"), default="sudo",
                      help="повышение прав для аудита конфигураций: sudo (пароль "
                           "учётки через stdin; для ключа — NOPASSWD) или none "
                           "(по умолчанию sudo)")
    cadd.set_defaults(handler=cmd_credentials_add)
    clist = csub.add_parser("list", help="учётки договора (без секретов)")
    clist.add_argument("--engagement", required=True, type=int, help="id договора")
    clist.set_defaults(handler=cmd_credentials_list)
    cdel = csub.add_parser("delete", help="удалить учётку")
    cdel.add_argument("--engagement", required=True, type=int, help="id договора")
    cdel.add_argument("--id", required=True, type=int, dest="credential_id")
    cdel.set_defaults(handler=cmd_credentials_delete)

    # --- report ---
    rep = sub.add_parser("report", help="выгрузить отчёт по завершённому прогону")
    rep.add_argument("--run", required=True, type=int, dest="run_id", help="id прогона")
    rep.add_argument("--format", default="html", choices=REPORT_FORMATS)
    rep.add_argument("--out", type=Path,
                     help="файл отчёта (по умолчанию report-run-<id>.<формат>)")
    rep.add_argument("--compare-to", type=int, metavar="RUN_ID",
                     help="сравнить с указанным более ранним прогоном договора "
                          "(по умолчанию отчёт только по одному прогону)")
    rep.add_argument("--brief", action="store_true",
                     help="краткая версия: без плана устранения, вместо рекомендаций "
                          "только ссылки на устранение")
    rep.set_defaults(handler=cmd_report)
    return p


# ========== БД ==========
def _engine(url: str | None) -> Engine:
    from scanner.core.db import make_engine
    if url and url.startswith("sqlite"):
        from sqlalchemy import create_engine
        return create_engine(url, future=True)
    return make_engine(url)


def ensure_schema(engine: Engine) -> None:
    """Схема БД: Alembic для Postgres, ORM-метаданные для SQLite."""
    if engine.dialect.name == "sqlite":
        from scanner.core.db import Base
        from scanner.feeds.store import SqlReferenceStore
        Base.metadata.create_all(engine)
        SqlReferenceStore(engine).create_schema()
        return
    from alembic.config import Config

    from alembic import command

    if not ALEMBIC_INI.exists():
        raise CliError(f"не найден {ALEMBIC_INI}; примените миграции вручную "
                       "(alembic upgrade head) и запустите с --no-migrate")
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    # % в пароле — синтаксис интерполяции configparser
    url = engine.url.render_as_string(hide_password=False).replace("%", "%%")
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


class _Env:
    """Engine, фабрика сессий и аудит одной команды."""

    def __init__(self, args: argparse.Namespace):
        from scanner.core.audit import DbAuditSink
        from scanner.core.db import make_session_factory
        self.engine = _engine(args.db_url)
        if not args.no_migrate:
            ensure_schema(self.engine)
        self.sessions = make_session_factory(self.engine)
        self.audit = DbAuditSink(self.sessions)
        self.actor: str = args.actor


# ========== Команды ==========
def cmd_sync_bdu(args: argparse.Namespace, env: _Env) -> int:
    from scanner.feeds.bdu_fstec import BduFstecFeed
    from scanner.feeds.store import SqlReferenceStore

    if not args.file.is_file():
        raise CliError(f"файл не найден: {args.file}")
    try:
        n = BduFstecFeed(str(args.file)).sync(SqlReferenceStore(env.engine),
                                              batch_size=args.batch_size)
    except Exception as e:
        env.audit.record(subject=env.actor, action="feed_sync", target="bdu_fstec",
                         result="error", details={"file": args.file.name,
                                                  "error": f"{type(e).__name__}: {e}"[:500]})
        raise
    env.audit.record(subject=env.actor, action="feed_sync", target="bdu_fstec",
                     result="ok", details={"file": args.file.name, "records": n})
    print(f"БДУ ФСТЭК: загружено записей — {n}")
    return 0


def cmd_sync_nvd(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core.config import settings
    from scanner.feeds.nvd import NvdFeed
    from scanner.feeds.store import SqlReferenceStore

    if bool(args.since) != bool(args.until):
        raise CliError("--since и --until задаются вместе")
    if args.files and (args.cve or args.since):
        raise CliError("--file нельзя сочетать с --cve/--since: это выгрузка через API")
    missing = [str(f) for f in args.files if not f.is_file()]
    if missing:
        raise CliError(f"файл не найден: {', '.join(missing)}")

    api_key = args.api_key if args.api_key is not None else settings.nvd_api_key
    feed = NvdFeed(api_key, audit=env.audit)
    if args.files:
        source, details = feed.iter_files(args.files), {"files": [f.name for f in args.files]}
    else:
        source = feed.iter_api(last_mod_start=args.since, last_mod_end=args.until,
                               cve_id=args.cve)
        details = {"source": "api", "cve": args.cve,
                   "since": args.since.isoformat() if args.since else None,
                   "until": args.until.isoformat() if args.until else None}
    try:
        n = feed.sync(SqlReferenceStore(env.engine), records=source,
                      batch_size=args.batch_size)
    except Exception as e:
        env.audit.record(subject=env.actor, action="feed_sync", target="nvd",
                         result="error",
                         details={**details, "error": f"{type(e).__name__}: {e}"[:500]})
        raise
    env.audit.record(subject=env.actor, action="feed_sync", target="nvd", result="ok",
                     details={**details, "records": n})
    print(f"NVD: загружено CVE — {n}")
    return 0


def cmd_auto_enabled(args: argparse.Namespace, env: _Env) -> int:
    """Для entrypoint: при включённом расписании старт не дублирует обновление."""
    from sqlalchemy import select

    from scanner.core.db import FeedSync, session_scope
    with session_scope(env.sessions) as s:
        enabled = s.scalar(select(FeedSync.enabled).where(FeedSync.source == args.source))
    return 0 if enabled else 1


def _registry(env: _Env):
    """Реестр модулей; находки vuln и пакеты auth_inventory сопоставляются
    с CVE/БДУ из справочника в БД."""
    from scanner.core.orchestrator import default_module_registry
    from scanner.feeds.matcher import VulnMatcher
    from scanner.feeds.store import SqlReferenceStore

    return default_module_registry(matcher=VulnMatcher(SqlReferenceStore(env.engine)))


def cmd_run(args: argparse.Namespace, env: _Env, registry=None) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import Engagement, session_scope
    from scanner.core.orchestrator import RunService, inline_executor

    if not args.confirm_authorized:
        raise CliError("запуск только по целям из договора: подтвердите флагом "
                       "--confirm-authorized")
    if args.engine:
        engine_modules = {m for ms in VULN_ENGINES.values() for m in ms}
        args.modules = [*(m for m in args.modules if m not in engine_modules),
                        *VULN_ENGINES[args.engine]]
    if "cred_audit" in args.modules and not args.allow_cred_audit:
        raise CliError("cred_audit требует отдельного согласования: добавьте "
                       "--allow-cred-audit")
    if ((CREDENTIAL_MODULES & set(args.modules)) or args.credentials) \
            and not args.allow_credentials:
        raise CliError("вход на активы по учётным записям требует отдельного "
                       "согласования: добавьте --allow-credentials")

    with session_scope(env.sessions) as s:
        eng = s.get(Engagement, args.engagement)
        if eng is None:
            raise CliError(f"договор {args.engagement} не найден")
        eng_label = eng.contract_ref or eng.name
        if not repo.list_allowlist(s, args.engagement):
            raise CliError(f"у договора {args.engagement} пустой allowlist: "
                           "цели добавляет администратор")

    svc = RunService(env.sessions, env.audit,
                     registry=registry if registry is not None else _registry(env),
                     executor=inline_executor())
    plan = svc.preview(args.engagement, args.targets)
    for d in plan.denied:
        print(f"  отклонено: {d.target} ({d.reason}, адресов: {d.count})", file=sys.stderr)
    if not plan.allowed:
        env.audit.record(subject=env.actor, action="scan_queue",
                         target=f"engagement:{args.engagement}", result="denied",
                         details={"requested_targets": args.targets[:100],
                                  "reason": "no_allowed_targets"})
        raise CliError("ни одна цель не входит в allowlist договора — прогон не запущен")

    try:
        svc.check_credentials(args.engagement, args.modules, args.credentials)
    except ValueError as e:
        raise CliError(str(e)) from e
    print(f"Договор: {eng_label}. Целей к проверке: {len(plan.allowed)}, "
          f"модули: {' '.join(args.modules)}, профиль: {args.rate}")
    run_id = svc.submit(engagement_id=args.engagement, modules=args.modules,
                        rate_profile=args.rate, requested_targets=args.targets,
                        actor=env.actor, credential_ids=args.credentials,
                        name=args.name)
    with session_scope(env.sessions) as s:
        run = repo.get_scan_run(s, run_id)
        status, title = run.status, run.name
        findings = len(repo.get_findings(s, run_id))
    print(f"Прогон {run_id} «{title}»: {status}, находок — {findings}")
    if status != "done":
        print("Подробности ошибок модулей — в журнале аудита (scan_finish).",
              file=sys.stderr)
    return 0 if status == "done" else 1


def _resolver(env: _Env, findings):
    """Рекомендации по устранению из справочника БДУ ФСТЭК."""
    from scanner.feeds.store import SqlReferenceStore
    from scanner.reporting.remediation import RemediationResolver

    store = SqlReferenceStore(env.engine)
    ids = {b.upper() for f in findings for b in f.bdu_ids}
    ids |= {f.vuln_id.upper() for f in findings
            if f.vuln_id and f.vuln_id.upper().startswith("BDU:")}
    bdu = {}
    for bid in sorted(ids):
        rec = store.get_bdu(bid)
        if rec is not None:
            bdu[bid] = rec
    return RemediationResolver(bdu=bdu)


def cmd_report(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import Engagement, session_scope
    from scanner.reporting.model import ReportContext, build_report
    from scanner.reporting.render import ReportRenderer

    with session_scope(env.sessions) as s:
        run = repo.get_scan_run(s, args.run_id)
        if run is None:
            raise CliError(f"прогон {args.run_id} не найден")
        if run.status not in FINISHED:
            raise CliError(f"прогон в статусе {run.status}; отчёт доступен после завершения")
        eng = s.get(Engagement, run.engagement_id)
        current = repo.get_findings(s, args.run_id)
        prev_id = None
        if args.compare_to is not None:
            try:
                prev_id = repo.comparison_baseline(s, run, args.compare_to).id
            except ValueError as e:
                raise CliError(str(e)) from e
        previous = repo.get_findings(s, prev_id) if prev_id is not None else None
        hist = (repo.historically_fixed_keys(s, eng.id, prev_id)
                if prev_id is not None else None)
        context = ReportContext(customer=eng.client, engagement=eng.contract_ref or eng.name,
                                run_id=args.run_id, previous_run_id=prev_id)
        marks = repo.false_positive_marks(s, eng.id)

    report = build_report(current, previous=previous, historically_fixed=hist,
                          resolver=_resolver(env, current), context=context,
                          false_positives=marks)
    variant = "brief" if args.brief else "full"
    try:
        body = ReportRenderer().render(report, args.format, variant=variant)
    except RuntimeError as e:   # PDF без Pango
        raise CliError(str(e)) from e
    suffix = ("-brief" if args.brief else "") + (f"-vs-{prev_id}" if prev_id is not None else "")
    out = args.out or Path(f"report-run-{args.run_id}{suffix}.{args.format}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(body)
    env.audit.record(subject=env.actor, action="export", target=f"scan_run:{args.run_id}",
                     result="ok", details={"format": args.format, "variant": variant,
                                           "previous_run_id": prev_id,
                                           "findings": len(current), "file": out.name})
    print(f"Отчёт: {out} ({len(body)} байт, находок — {len(current)})")
    return 0


def _vault():
    from scanner.core.credentials import load_vault
    vault = load_vault()
    if vault is None:
        raise CliError("не задан ключ шифрования учётных записей: SCANNER_CREDENTIALS_KEY "
                       "(или SCANNER_API_SECRET), не короче 16 символов")
    return vault


def _engagement_or_fail(env: _Env, engagement_id: int) -> None:
    from scanner.core.db import Engagement, session_scope
    with session_scope(env.sessions) as s:
        if s.get(Engagement, engagement_id) is None:
            raise CliError(f"договор {engagement_id} не найден")


def cmd_credentials_add(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.credentials import AUTH_KEY, AUTH_PASSWORD, CredentialError
    from scanner.core.db import session_scope

    vault = _vault()
    _engagement_or_fail(env, args.engagement)
    password = private_key = passphrase = None
    if args.key_file:
        if not args.key_file.is_file():
            raise CliError(f"файл ключа не найден: {args.key_file}")
        auth, private_key = AUTH_KEY, args.key_file.read_text()
        if args.passphrase_env:
            passphrase = os.environ.get(args.passphrase_env) or None
    else:
        auth = AUTH_PASSWORD
        password = (os.environ.get(args.password_env) if args.password_env
                    else getpass.getpass(f"Пароль {args.username}: "))
        if not password:
            raise CliError("пустой пароль")
    try:
        with session_scope(env.sessions) as s:
            cid = repo.create_host_credential(
                s, vault, engagement_id=args.engagement, name=args.name, auth=auth,
                username=args.username, port=args.port, targets=args.targets,
                password=password, private_key=private_key, passphrase=passphrase,
                become=args.become)
            row = repo.list_host_credentials(s, args.engagement)[-1]
            fingerprint, targets = row.key_fingerprint, list(row.targets or [])
    except CredentialError as e:
        raise CliError(str(e)) from e
    env.audit.record(subject=env.actor, action="credential_create",
                     target=f"engagement:{args.engagement}", result="ok",
                     details={"credential_id": cid, "name": args.name,
                              "user": args.username, "port": args.port, "auth": auth,
                              "become": args.become,
                              "targets": targets, "key_fingerprint": fingerprint})
    print(f"Учётная запись {cid} заведена: {args.username}, порт {args.port}, {auth}, "
          f"повышение прав: {args.become}"
          + (f", {fingerprint}" if fingerprint else ""))
    return 0


def cmd_credentials_list(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import session_scope

    _engagement_or_fail(env, args.engagement)
    with session_scope(env.sessions) as s:
        rows = repo.list_host_credentials(s, args.engagement)
        for r in rows:
            scope = ", ".join(str(t) for t in r.targets or []) or "все цели прогона"
            print(f"{r.id}\t{r.name}\t{r.username}:{r.port}\t{r.auth}\t"
                  f"become={r.become}\t{scope}"
                  + (f"\t{r.key_fingerprint}" if r.key_fingerprint else ""))
    if not rows:
        print("У договора нет учётных записей.")
    return 0


def cmd_credentials_delete(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core.db import HostCredentialRow, session_scope

    with session_scope(env.sessions) as s:
        row = s.get(HostCredentialRow, args.credential_id)
        if row is None or row.engagement_id != args.engagement:
            raise CliError(f"учётная запись {args.credential_id} не найдена в договоре")
        name = row.name
        s.delete(row)
    env.audit.record(subject=env.actor, action="credential_delete",
                     target=f"engagement:{args.engagement}", result="ok",
                     details={"credential_id": args.credential_id, "name": name})
    print(f"Учётная запись {args.credential_id} удалена")
    return 0


# ========== Точка входа ==========
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        env = _Env(args)
        try:
            return args.handler(args, env)
        finally:
            env.engine.dispose()
    except CliError as e:
        print(f"scanner: ошибка: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
