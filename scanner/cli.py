"""Операционный CLI: загрузка справочников, запуск прогона, выгрузка отчёта.

    scanner feeds sync-bdu --file vullist.xlsx
    scanner feeds sync-nvd [--file nvdcve-2.0-2024.json.gz ...] [--since ... --until ...]
    scanner feeds sync-advisories [--release debian:bookworm ...] [--file oval.xml.bz2]
    scanner run --engagement 1 --targets 10.0.0.0/28 10.0.0.50 --modules discovery vuln \\
                --confirm-authorized
    scanner report --run 7 --format pdf [--out report.pdf] [--brief]
    scanner credentials add --engagement 1 --name "root на 10.0.0.0/24" --user audit \
                --key-file ~/.ssh/id_ed25519 [--targets 10.0.0.0/24]
    scanner run --engagement 1 --targets 10.0.0.0/24 --engine credentialed --credential 1 \
                --confirm-authorized --allow-credentials
    scanner run --engagement 1 --targets 10.0.0.0/24 --modules discovery config_audit \
                --credential 1 --confirm-authorized --allow-credentials
    scanner credentials add --engagement 1 --name "Windows ДМЗ" --protocol winrm \
                --user 'CORP\audit' --ask-password [--targets 10.0.2.0/24]
    scanner feeds sync-msrc [--file 2024-Jan.json ...]
    scanner feeds sync nvd epss kev advisories     # как автообновление, с учётом даты
    scanner bundle export --out data/bundle/scanner-data-20261103.tar
    scanner bundle import [scanner-data-20261103.tar] [--auto] [--force]
    scanner bundle info scanner-data-20261103.tar

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
FINISHED = {"done", "partial", "failed", "stopped", "interrupted"}


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

    msrc = fsub.add_parser("sync-msrc", help="загрузить бюллетени обновлений Microsoft "
                                             "(MSRC CVRF: KB, CVE, замещение)")
    msrc.add_argument("--file", dest="files", action="append", type=Path, default=[],
                      help="документ CVRF JSON или каталог с *.json; можно несколько "
                           "раз. Без --file — загрузка через API MSRC")
    msrc.add_argument("--since", default=None,
                      help="с какого бюллетеня грузить через API, напр. 2023-Jan "
                           "(по умолчанию SCANNER_MSRC_SINCE)")
    msrc.set_defaults(handler=cmd_sync_msrc)

    adv = fsub.add_parser("sync-advisories",
                          help="загрузить бюллетени дистрибутивов (учёт бэкпортов)")
    adv.add_argument("--release", dest="releases", action="append", default=[],
                     metavar="СЕМЕЙСТВО:ВЫПУСК",
                     help="выпуск, напр. debian:bookworm, rhel:9, astra:1.7; можно "
                          "несколько раз. По умолчанию — ADVISORY_RELEASES")
    adv.add_argument("--file", type=Path,
                     help="локальный файл (OVAL .xml[.bz2|.gz|.zip] или JSON трекера "
                          "Debian) для одного семейства из --release")
    adv.set_defaults(handler=cmd_sync_advisories)

    auto = fsub.add_parser("auto-enabled", help="включено ли автообновление источника "
                                                "по расписанию (код 0 — да, 1 — нет)")
    auto.add_argument("source", help="bdu | nvd | nuclei | advisories")
    auto.set_defaults(handler=cmd_auto_enabled)

    sync = fsub.add_parser("sync", help="обновить источники так же, как автообновление "
                                        "(инкремент NVD/MSRC от прошлой загрузки, "
                                        "итог — в «Справочниках»)")
    sync.add_argument("sources", nargs="+", metavar="ИСТОЧНИК",
                      help="bdu | nvd | nuclei | msrc | epss | kev | advisories")
    sync.set_defaults(handler=cmd_feeds_sync)

    # --- bundle ---
    bundle = sub.add_parser("bundle", help="комплект данных уязвимостей для поставки "
                                           "(снимок справочников одним файлом)")
    bsub = bundle.add_subparsers(dest="bundle_command", required=True,
                                 metavar="bundle_command")
    bexp = bsub.add_parser("export", help="собрать комплект из справочников в БД")
    bexp.add_argument("--out", required=True, type=Path,
                      help="файл комплекта, напр. data/bundle/scanner-data-20261103.tar")
    bexp.add_argument("--source", dest="sources", action="append", default=[],
                      help="только этот источник (bdu, nvd, epss, kev, msrc, "
                           "advisories); можно несколько раз. По умолчанию — все")
    bexp.add_argument("--nuclei-templates", type=Path, default=None,
                      help="каталог шаблонов Nuclei для комплекта (по умолчанию — "
                           "каталог Nuclei этой установки, если он есть)")
    bexp.add_argument("--no-nuclei", action="store_true",
                      help="не класть шаблоны Nuclei в комплект")
    bexp.set_defaults(handler=cmd_bundle_export)

    bimp = bsub.add_parser("import", help="загрузить справочники из комплекта")
    bimp.add_argument("file", nargs="?", type=Path,
                      help="файл комплекта; без него — самый свежий scanner-data-*.tar "
                           "в каталогах --dir")
    bimp.add_argument("--dir", dest="dirs", action="append", default=[],
                      help="где искать комплект (по умолчанию /data/bundle и "
                           "/app/docker/data-bundle)")
    bimp.add_argument("--url", default=os.environ.get("SCANNER_DATA_BUNDLE_URL", ""),
                      help="скачать комплект, если в каталогах его нет "
                           "(по умолчанию SCANNER_DATA_BUNDLE_URL)")
    bimp.add_argument("--source", dest="sources", action="append", default=[],
                      help="только этот источник; можно несколько раз")
    bimp.add_argument("--force", action="store_true",
                      help="заменить и более свежие локальные данные")
    bimp.add_argument("--auto", action="store_true",
                      help="режим старта контейнера: нет комплекта — не ошибка")
    bimp.add_argument("--nuclei-templates", type=Path, default=None,
                      help="куда разложить шаблоны Nuclei из комплекта")
    bimp.add_argument("--bdu-marker", type=Path, default=None,
                      help="создать этот файл, если БДУ загружена из комплекта (метка "
                           "entrypoint: старая vullist.xlsx из ./data не перезапишет "
                           "более свежую БДУ комплекта)")
    bimp.set_defaults(handler=cmd_bundle_import)

    binfo = bsub.add_parser("info", help="что внутри комплекта")
    binfo.add_argument("file", type=Path)
    binfo.set_defaults(handler=cmd_bundle_info)

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
    run.add_argument("--cred-set", type=int, action="append", default=[],
                     dest="cred_sets", metavar="ID",
                     help="набор проверки учёток для cred_audit (можно несколько)")
    run.add_argument("--name", help="имя прогона (по умолчанию — по модулям и целям)")
    run.add_argument("--no-ping", action="store_true",
                     help="сканировать хосты, не отвечающие на ICMP (nmap -Pn); дольше: "
                          "выключенные адреса сканируются по портам до таймаута")
    run.set_defaults(handler=cmd_run)

    # --- credentials ---
    cred = sub.add_parser("credentials", help="учётные записи активов договора")
    csub = cred.add_subparsers(dest="credentials_command", required=True, metavar="action")
    cadd = csub.add_parser("add", help="завести учётку (SSH: пароль или ключ; "
                                       "WinRM: пароль)")
    cadd.add_argument("--engagement", required=True, type=int, help="id договора")
    cadd.add_argument("--name", required=True, help="название учётки")
    cadd.add_argument("--user", required=True, dest="username", help="логин на активе")
    cadd.add_argument("--protocol", choices=("ssh", "winrm", "netssh", "snmp"),
                      default="ssh",
                      help="способ входа: ssh (Linux/Unix), winrm (Windows, "
                           "HTTPS + NTLM, логин ДОМЕН\\user), netssh (CLI сетевого "
                           "устройства по SSH), snmp (SNMPv2c/v3, только чтение); "
                           "по умолчанию ssh")
    cadd.add_argument("--port", type=int, default=None,
                      help="порт (по умолчанию SSH 22, WinRM HTTPS 5986, SNMP 161)")
    cadd.add_argument("--platform", default="auto",
                      help="netssh: платформа устройства (auto, cisco_ios, cisco_xe, "
                           "cisco_nxos, cisco_asa, junos, routeros, huawei_vrp, "
                           "eltex_esr, eltex_mes); по умолчанию auto")
    cadd.add_argument("--snmp-version", choices=("2c", "3"), default="3",
                      help="snmp: версия (2c — community в пароле; 3 — USM)")
    cadd.add_argument("--snmp-auth", default="sha",
                      help="snmp v3: алгоритм аутентификации (sha, sha256, sha512, md5…)")
    cadd.add_argument("--snmp-priv", default="aes",
                      help="snmp v3: алгоритм шифрования (aes, aes256, aes256c, des, none)")
    cadd.add_argument("--priv-env", metavar="VAR",
                      help="snmp v3: ключ шифрования (priv) из переменной окружения VAR")
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

    # --- cred-sets (наборы проверки учёток для аудита паролей) ---
    cs = sub.add_parser("cred-sets", help="наборы проверки учёток (аудит паролей)")
    cssub = cs.add_subparsers(dest="cred_sets_command", required=True, metavar="action")
    csadd = cssub.add_parser("add", help="завести набор из файла (строки логин:секрет)")
    csadd.add_argument("--engagement", required=True, type=int, help="id договора")
    csadd.add_argument("--name", required=True, help="название набора")
    csadd.add_argument("--file", required=True, type=Path, dest="entries_file",
                       help="файл: по строке на запись «логин:секрет» "
                            "(пустой пароль — строка «логин:»); # — комментарий")
    csadd.add_argument("--service", action="append", default=[], dest="services",
                       metavar="SERVICE",
                       help="сервис, к которому применять набор (можно несколько; "
                            "по умолчанию — все поддерживаемые)")
    csadd.set_defaults(handler=cmd_cred_sets_add)
    cslist = cssub.add_parser("list", help="наборы договора (без секретов)")
    cslist.add_argument("--engagement", required=True, type=int, help="id договора")
    cslist.set_defaults(handler=cmd_cred_sets_list)
    csdel = cssub.add_parser("delete", help="удалить набор")
    csdel.add_argument("--engagement", required=True, type=int, help="id договора")
    csdel.add_argument("--id", required=True, type=int, dest="set_id")
    csdel.set_defaults(handler=cmd_cred_sets_delete)

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
    rep.add_argument("--no-plan", action="store_true",
                     help="без раздела «План устранения» (рекомендации по находкам остаются)")
    rep.set_defaults(handler=cmd_report)

    # --- auth ---
    auth = sub.add_parser("auth", help="проверка входа через LDAP/AD")
    asub = auth.add_subparsers(dest="auth_command", required=True, metavar="action")
    lchk = asub.add_parser(
        "ldap-check", help="проверить настройки LDAP/AD из окружения: связь с каталогом, "
                           "служебную учётку и (с --username) вход и роли пользователя")
    lchk.add_argument("--username", help="логин пользователя домена для пробного входа")
    lchk.add_argument("--password-stdin", action="store_true",
                      help="пароль пользователя — из stdin (иначе спросит без эха)")
    lchk.set_defaults(handler=cmd_auth_ldap_check, no_db=True)
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


def cmd_sync_msrc(args: argparse.Namespace, env: _Env) -> int:
    from scanner.feeds.msrc import MsrcFeed, MsrcStore, msrc_settings

    missing = [str(f) for f in args.files if not f.exists()]
    if missing:
        raise CliError(f"файл не найден: {', '.join(missing)}")
    cfg = msrc_settings()
    store = MsrcStore(env.engine)
    if env.engine.dialect.name == "sqlite":
        store.create_schema()
    feed = MsrcFeed(cfg.api_url)
    if args.files:
        docs, details = feed.iter_files(args.files), {"files": [f.name for f in args.files]}
    else:
        since = args.since or cfg.since
        docs, details = feed.iter_api(since=since), {"source": "api", "since": since}
    try:
        n_docs, n_fixes = feed.sync(store, docs)
    except Exception as e:
        env.audit.record(subject=env.actor, action="feed_sync", target="msrc",
                         result="error",
                         details={**details, "error": f"{type(e).__name__}: {e}"[:500]})
        raise
    env.audit.record(subject=env.actor, action="feed_sync", target="msrc", result="ok",
                     details={**details, "releases": n_docs, "records": n_fixes})
    print(f"MSRC: бюллетеней — {n_docs}, исправлений для Windows — {n_fixes}")
    return 0
def cmd_sync_advisories(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core.config import settings
    from scanner.feeds.advisories import FAMILIES
    from scanner.feeds.advisories.store import SqlAdvisoryStore
    from scanner.feeds.advisories.sync import (
        AdvisoryError,
        Job,
        parse_targets,
        run_job,
        sync_releases,
    )

    try:
        targets = parse_targets(",".join(args.releases) or settings.advisory_releases)
    except AdvisoryError as e:
        raise CliError(str(e)) from e
    if not targets:
        raise CliError("не заданы выпуски: --release или ADVISORY_RELEASES")
    store = SqlAdvisoryStore(env.engine)
    if args.file is not None:
        if not args.file.is_file():
            raise CliError(f"файл не найден: {args.file}")
        families = {f for f, _ in targets}
        if len(families) != 1:
            raise CliError("--file: укажите выпуски одного семейства (--release)")
        try:
            results, _ = run_job(Job(FAMILIES[families.pop()], [r for _, r in targets],
                                      path=args.file), store)
        except Exception as e:
            raise CliError(f"{args.file.name}: {type(e).__name__}: {e}") from e
    else:
        directory = Path(settings.advisory_dir) if settings.advisory_dir else None
        results, _ = sync_releases(store, targets, directory=directory,
                                   urls=settings.advisory_urls())
    for r in results:
        if r.error:
            print(f"{r.family}:{r.release}: ошибка — {r.error}", file=sys.stderr)
        else:
            print(f"{r.family}:{r.release}: записей — {r.count} ({r.source})")
    ok = [r for r in results if not r.error]
    env.audit.record(subject=env.actor, action="feed_sync", target="feed:advisories",
                     result="ok" if ok else "error",
                     details={"releases": [f"{r.family}:{r.release}" for r in results],
                              "records": sum(r.count for r in ok),
                              "errors": [f"{r.family}:{r.release}: {r.error}"[:200]
                                         for r in results if r.error] or None})
    return 0 if len(ok) == len(results) else 1


def cmd_auto_enabled(args: argparse.Namespace, env: _Env) -> int:
    """Для entrypoint: при включённом расписании старт не дублирует обновление."""
    from sqlalchemy import select

    from scanner.core.db import FeedSync, session_scope
    with session_scope(env.sessions) as s:
        enabled = s.scalar(select(FeedSync.enabled).where(FeedSync.source == args.source))
    return 0 if enabled else 1


def _api_timezone() -> str:
    """Пояс расписаний по умолчанию — тот же, что заводит API (SCANNER_API_TIMEZONE)."""
    from scanner.api.settings import ApiSettings
    return ApiSettings().timezone


def cmd_feeds_sync(args: argparse.Namespace, env: _Env) -> int:
    """Загрузка источников через те же загрузчики и учёт, что у автообновления:
    дата успешной загрузки и отпечаток пишутся в feed_sync (NVD и MSRC дальше
    докачивают только изменения; комплект данных берёт отсюда «актуально на»)."""
    from datetime import UTC

    from sqlalchemy import select

    from scanner.core.db import FeedSync, session_scope
    from scanner.feeds.scheduler import FeedScheduler, seed_feed_sync
    from scanner.feeds.sources import SOURCES

    unknown = [s for s in args.sources if s not in SOURCES]
    if unknown:
        raise CliError(f"неизвестные источники: {', '.join(unknown)} "
                       f"(доступны: {', '.join(SOURCES)})")
    seed_feed_sync(env.sessions, timezone=_api_timezone())
    sched = FeedScheduler(env.sessions, env.audit, tick_seconds=0)
    failed = 0
    try:
        for source in dict.fromkeys(args.sources):
            outcome = sched.execute(source, datetime.now(UTC), env.actor, manual=True)
            with session_scope(env.sessions) as s:
                msg = s.scalar(select(FeedSync.message).where(FeedSync.source == source))
            print(f"{source}: {outcome} — {msg or ''}")
            failed += outcome == "error"
    finally:
        sched.stop()
    return 1 if failed else 0


def _nuclei_dir(arg: Path | None) -> Path:
    if arg is not None:
        return arg
    from scanner.feeds.sources import nuclei_templates_dir
    return nuclei_templates_dir()


def cmd_bundle_export(args: argparse.Namespace, env: _Env) -> int:
    from importlib.metadata import PackageNotFoundError, version

    from scanner.feeds.bundle import BundleError, export_bundle

    try:
        ver = version("scanner")
    except PackageNotFoundError:  # pragma: no cover
        ver = ""
    nuclei = None if args.no_nuclei else _nuclei_dir(args.nuclei_templates)
    try:
        res = export_bundle(env.engine, args.out, sources=args.sources or None,
                            nuclei_dir=nuclei, scanner_version=ver)
    except BundleError as e:
        raise CliError(str(e)) from e
    size = res.path.stat().st_size
    for sid, entry in res.manifest["sources"].items():
        print(f"{sid}: {entry['count']} записей, актуально на {entry['as_of'][:10]}")
    if "nuclei_templates" in res.manifest:
        print(f"nuclei: {res.manifest['nuclei_templates']['count']} шаблонов")
    if res.skipped:
        print(f"пропущены (нет данных): {', '.join(res.skipped)}")
    print(f"комплект: {res.path} ({size / 1_048_576:.1f} МБ)")
    env.audit.record(subject=env.actor, action="feed_bundle_export", target="bundle",
                     result="ok", details={"file": res.path.name, "bytes": size,
                                           "sources": sorted(res.manifest["sources"])})
    return 0


def cmd_bundle_import(args: argparse.Namespace, env: _Env) -> int:
    from scanner.feeds.bundle import (
        DEFAULT_DIRS,
        BundleError,
        download_bundle,
        find_bundle,
        import_bundle,
    )

    dirs = args.dirs or list(DEFAULT_DIRS)
    path = args.file
    try:
        if path is None:
            path = find_bundle(dirs)
        if path is None and args.url.strip():
            print(f"комплект не найден в {', '.join(dirs)} — скачиваю {args.url.strip()}")
            path = download_bundle(args.url.strip(), Path(dirs[0]))
        if path is None:
            if args.auto:
                print("комплект данных не найден — справочники загрузятся из источников")
                return 0
            raise CliError(f"комплект не найден в {', '.join(dirs)}; укажите файл")
        if not Path(path).is_file():
            raise CliError(f"файл не найден: {path}")
        results = import_bundle(env.engine, Path(path), sources=args.sources or None,
                                force=args.force,
                                nuclei_dir=_nuclei_dir(args.nuclei_templates),
                                timezone=_api_timezone())
    except BundleError as e:
        env.audit.record(subject=env.actor, action="feed_bundle_import", target="bundle",
                         result="error", details={"file": Path(path).name if path else None,
                                                  "error": str(e)[:300]})
        raise CliError(str(e)) from e
    for r in results:
        verb = "загружено" if r.status == "imported" else "пропущено"
        print(f"{r.source}: {verb} — {r.message}")
    if args.bdu_marker and any(r.source == "bdu" and r.status == "imported"
                               for r in results):
        try:
            args.bdu_marker.touch()
        except OSError:
            pass
    env.audit.record(subject=env.actor, action="feed_bundle_import", target="bundle",
                     result="ok", details={
                         "file": Path(path).name,
                         "imported": {r.source: r.count for r in results
                                      if r.status == "imported"},
                         "skipped": [r.source for r in results if r.status != "imported"]
                         or None})
    return 0


def cmd_bundle_info(args: argparse.Namespace, env: _Env) -> int:
    from scanner.feeds.bundle import BundleError, read_manifest

    try:
        m = read_manifest(args.file)
    except BundleError as e:
        raise CliError(str(e)) from e
    print(f"комплект от {m['created_at'][:10]}, формат {m['format']}, "
          f"версия сканера {m.get('scanner_version') or '—'}")
    for sid, entry in m["sources"].items():
        extra = f"; выпуски: {', '.join(entry['releases'])}" if entry.get("releases") else ""
        print(f"  {sid}: {entry['count']} записей, актуально на "
              f"{(entry.get('as_of') or '')[:10]}{extra}")
    if m.get("nuclei_templates"):
        print(f"  nuclei: {m['nuclei_templates']['count']} шаблонов")
    return 0


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
        known = set(registry) if registry is not None else None
        args.modules = [*(m for m in args.modules if m not in engine_modules),
                        *(m for m in VULN_ENGINES[args.engine]
                          if known is None or m in known)]
    cred_sets = list(getattr(args, "cred_sets", []) or [])
    if ("cred_audit" in args.modules or cred_sets) and not args.allow_cred_audit:
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
        svc.check_cred_sets(args.engagement, cred_sets)
    except ValueError as e:
        raise CliError(str(e)) from e
    print(f"Договор: {eng_label}. Целей к проверке: {len(plan.allowed)}, "
          f"модули: {' '.join(args.modules)}, профиль: {args.rate}")
    run_id = svc.submit(engagement_id=args.engagement, modules=args.modules,
                        rate_profile=args.rate, requested_targets=args.targets,
                        actor=env.actor, credential_ids=args.credentials,
                        cred_set_ids=cred_sets, name=args.name,
                        options={"no_ping": getattr(args, "no_ping", False)})
    with session_scope(env.sessions) as s:
        run = repo.get_scan_run(s, run_id)
        status, title, error = run.status, run.name, run.error_message
        warnings = [w.get("message") for w in run.warnings or [] if w.get("message")]
        findings = len(repo.get_findings(s, run_id))
    print(f"Прогон {run_id} «{title}»: {status}, находок — {findings}")
    for w in warnings:
        print(f"Внимание: {w}", file=sys.stderr)
    if status != "done":
        if error:
            print(error, file=sys.stderr)
        print("Подробности — покрытие прогона (GET /runs/{id}/coverage) и журнал аудита "
              "(scan_finish).", file=sys.stderr)
    # 0 — выполнен полностью, 2 — частично (есть пробелы покрытия), 1 — ошибка
    return {"done": 0, "partial": 2}.get(status, 1)


def _resolver(env: _Env, findings):
    """Рекомендации по устранению из справочника БДУ ФСТЭК."""
    from scanner.feeds.store import SqlReferenceStore
    from scanner.reporting.remediation import RemediationResolver, host_os_from_findings

    store = SqlReferenceStore(env.engine)
    ids = {b.upper() for f in findings for b in f.bdu_ids}
    ids |= {f.vuln_id.upper() for f in findings
            if f.vuln_id and f.vuln_id.upper().startswith("BDU:")}
    bdu = {}
    for bid in sorted(ids):
        rec = store.get_bdu(bid)
        if rec is not None:
            bdu[bid] = rec
    return RemediationResolver(bdu=bdu, host_os=host_os_from_findings(findings))


def cmd_report(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import Engagement, session_scope
    from scanner.reporting.model import ReportContext, build_report
    from scanner.reporting.render import ReportRenderer
    from scanner.reporting.risk import build_risk_context

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
        risk = build_risk_context(s, current, eng.id)
        os_names = repo.host_os_names(s, eng.id)
        coverage = repo.run_coverage(s, run)
        prev_cov = repo.run_coverage(s, prev_id) if prev_id is not None else None
        run_status, run_warnings = run.status, list(run.warnings or [])

    resolver = _resolver(env, current)
    resolver.add_host_os(os_names, override=False)
    report = build_report(current, previous=previous, historically_fixed=hist,
                          resolver=resolver, context=context,
                          false_positives=marks, risk=risk, with_plan=not args.no_plan,
                          coverage=coverage, previous_coverage=prev_cov,
                          run_status=run_status, warnings=run_warnings)
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
        if args.protocol == "snmp" and args.snmp_version == "3":
            passphrase = (os.environ.get(args.priv_env) if args.priv_env else None)
            if passphrase is None and args.snmp_priv != "none":
                passphrase = getpass.getpass("Ключ шифрования SNMPv3 (priv): ") or None
    options = {}
    if args.protocol == "netssh":
        options = {"platform": args.platform}
    elif args.protocol == "snmp":
        options = {"snmp_version": args.snmp_version, "auth_proto": args.snmp_auth,
                   "priv_proto": args.snmp_priv}
    try:
        with session_scope(env.sessions) as s:
            cid = repo.create_host_credential(
                s, vault, engagement_id=args.engagement, name=args.name, auth=auth,
                username=args.username, port=args.port, targets=args.targets,
                password=password, private_key=private_key, passphrase=passphrase,
                become=args.become, protocol=args.protocol, options=options)
            row = repo.list_host_credentials(s, args.engagement)[-1]
            fingerprint, targets = row.key_fingerprint, list(row.targets or [])
            port, become = row.port, row.become
    except CredentialError as e:
        raise CliError(str(e)) from e
    env.audit.record(subject=env.actor, action="credential_create",
                     target=f"engagement:{args.engagement}", result="ok",
                     details={"credential_id": cid, "name": args.name,
                              "user": args.username, "port": port, "auth": auth,
                              "become": become, "protocol": args.protocol,
                              "targets": targets, "key_fingerprint": fingerprint})
    print(f"Учётная запись {cid} заведена: {args.protocol} {args.username}, порт {port}, "
          f"{auth}, повышение прав: {become}"
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
            print(f"{r.id}\t{r.name}\t{r.protocol}\t{r.username}:{r.port}\t{r.auth}\t"
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


# ========== Наборы проверки учёток (аудит паролей) ==========
def parse_cred_set_file(path: Path) -> list[tuple[str, str]]:
    """Файл набора -> пары (логин, секрет). По строке на запись «логин:секрет».

    Первое двоеточие делит логин и секрет (секрет может содержать двоеточия);
    «логин:» — пустой пароль. Пустые строки и строки с # в начале пропускаются.
    Секрет в сообщения об ошибках и в журнал не попадает.
    """
    if not path.is_file():
        raise CliError(f"файл набора не найден: {path}")
    entries: list[tuple[str, str]] = []
    for n, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise CliError(f"строка {n}: ожидается «логин:секрет» (нет двоеточия)")
        user, _, secret = line.partition(":")
        entries.append((user.strip(), secret))
    if not entries:
        raise CliError("в файле нет записей логин:секрет")
    return entries


def cmd_cred_sets_add(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.credentials import CredentialError
    from scanner.core.db import session_scope

    vault = _vault()
    _engagement_or_fail(env, args.engagement)
    entries = parse_cred_set_file(args.entries_file)
    try:
        with session_scope(env.sessions) as s:
            sid = repo.create_cred_audit_set(
                s, vault, engagement_id=args.engagement, name=args.name,
                entries=entries, services=args.services)
            row = repo.get_cred_audit_set(s, args.engagement, sid)
            count, services = row.entry_count, list(row.services or [])
    except CredentialError as e:
        raise CliError(str(e)) from e
    env.audit.record(subject=env.actor, action="cred_set_create",
                     target=f"engagement:{args.engagement}", result="ok",
                     details={"cred_set_id": sid, "name": args.name,
                              "services": services, "entry_count": count})
    svc = ", ".join(services) or "все поддерживаемые"
    print(f"Набор {sid} «{args.name}» заведён: записей — {count}, сервисы: {svc}")
    print("Секреты зашифрованы; в журнал и в вывод они не попадают.")
    return 0


def cmd_cred_sets_list(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import session_scope

    _engagement_or_fail(env, args.engagement)
    with session_scope(env.sessions) as s:
        rows = repo.list_cred_audit_sets(s, args.engagement)
        for r in rows:
            svc = ", ".join(r.services or []) or "все поддерживаемые"
            print(f"{r.id}\t{r.name}\tзаписей: {r.entry_count}\t{svc}")
    if not rows:
        print("У договора нет наборов проверки учёток.")
    return 0


def cmd_cred_sets_delete(args: argparse.Namespace, env: _Env) -> int:
    from scanner.core import repository as repo
    from scanner.core.db import session_scope

    with session_scope(env.sessions) as s:
        row = repo.get_cred_audit_set(s, args.engagement, args.set_id)
        if row is None:
            raise CliError(f"набор {args.set_id} не найден в договоре")
        name = row.name
        s.delete(row)
    env.audit.record(subject=env.actor, action="cred_set_delete",
                     target=f"engagement:{args.engagement}", result="ok",
                     details={"cred_set_id": args.set_id, "name": name})
    print(f"Набор {args.set_id} удалён")
    return 0


# ========== Точка входа ==========
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if getattr(args, "no_db", False):
            return args.handler(args, None)
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


def cmd_auth_ldap_check(args: argparse.Namespace, env: _Env | None) -> int:
    """Проверка LDAP без запуска API. Пароли не печатаются и не пишутся в журнал."""
    import getpass

    from scanner.api.ldap_auth import (
        LdapAuthenticator,
        LdapConfig,
        LdapConfigError,
        LdapDenied,
        LdapUnavailable,
    )
    from scanner.api.settings import ApiSettings

    try:
        cfg = LdapConfig.from_settings(ApiSettings())
    except LdapConfigError as e:
        raise CliError(f"настройки LDAP: {e}") from None
    if cfg is None:
        print("LDAP выключен: SCANNER_API_LDAP_URL не задан (вход только локальными учётками).")
        return 0
    print(f"Каталог: {', '.join(cfg.urls)}{' + STARTTLS' if cfg.start_tls else ''}"
          f"{'' if cfg.tls_verify else ' (сертификат НЕ проверяется)'}")
    print(f"Поиск: {cfg.user_base}  {cfg.user_filter}")
    for dn, roles in sorted(cfg.group_roles.items()):
        print(f"  группа {dn} => {', '.join(sorted(roles))}")
    auth = LdapAuthenticator(cfg)
    try:
        conn = auth.service_connection()
        conn.unbind()
        print(f"Служебная учётка: OK ({cfg.bind_dn or 'анонимно'})")
        if not args.username:
            return 0
        password = (sys.stdin.readline().rstrip("\n") if args.password_stdin
                    else getpass.getpass(f"Пароль {args.username}: "))
        ident = auth.authenticate(args.username, password)
    except LdapUnavailable as e:
        print(f"Каталог недоступен: {e}", file=sys.stderr)
        return 1
    except LdapDenied as e:
        reasons = {"bad_credentials": "неверный логин или пароль (или учётка отключена в домене)",
                   "not_found": "пользователь не найден по фильтру",
                   "ambiguous": "фильтр находит больше одного пользователя",
                   "no_group": "пользователь не состоит ни в одной группе из сопоставления"}
        print(f"Вход отклонён: {reasons.get(e.reason, e.reason)}", file=sys.stderr)
        return 1
    print(f"Вход: OK  логин в «Сканере»: {ident.username}  DN: {ident.dn}")
    print(f"Группы: {', '.join(ident.groups)}")
    print(f"Роли: {', '.join(sorted(ident.roles))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
