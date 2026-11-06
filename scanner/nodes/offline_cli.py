"""Команды автономного режима для `scanner` CLI (подключаются в scanner/nodes/cli.py).

Автономный узел (закрытый сегмент, связи с центром нет):

    scanner node init --name "АСУ-ТП-1" --scope 10.10.0.0/16 --center-key center.pub
    scanner node show
    scanner node inspect job-АСУ-ТП-1-run42-20261106-1200.scnjob
    scanner node run-job job-….scnjob --out /media/usb --confirm-authorized

Центр:

    scanner offline center-key [--out center.pub]

Каталог узла — `--home` или SCANNER_NODE_HOME (по умолчанию /var/lib/scanner-node).
Справочники для сопоставления с БДУ/CVE узел держит в своей БД (`--db-url`),
обновляются тем же комплектом данных: `scanner bundle import <файл>`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.nodes import offline_files as of
from scanner.nodes import offline_node as on


def add_offline_commands(sub, nsub) -> None:
    """sub — корневые подкоманды `scanner`, nsub — подкоманды `scanner node`."""

    def _home(p):
        p.add_argument("--home", type=Path, default=None,
                       help="каталог узла (по умолчанию SCANNER_NODE_HOME или "
                            f"{on.DEFAULT_HOME})")

    init = nsub.add_parser("init", help="установить автономный узел: ключи, сети узла, "
                                        "ключ центра")
    init.add_argument("--name", required=True, help="имя узла, как в центре («Сканеры»)")
    init.add_argument("--scope", required=True, nargs="+",
                      help="сети сегмента, которые узлу разрешено сканировать (CIDR/IP)")
    init.add_argument("--center-key", required=True, type=Path,
                      help="файл открытого ключа центра (center.pub из карточки узла "
                           "в «Сканерах»)")
    init.add_argument("--pub-out", type=Path, default=None,
                      help="куда ещё записать открытый ключ узла (например, на носитель)")
    init.add_argument("--force", action="store_true",
                      help="заменить ключи уже установленного узла")
    _home(init)
    init.set_defaults(handler=cmd_node_init, no_db=True)

    show = nsub.add_parser("show", help="имя, сети, отпечатки ключей и журнал узла")
    _home(show)
    show.set_defaults(handler=cmd_node_show, no_db=True)

    insp = nsub.add_parser("inspect", help="проверить файл задания, не выполняя его")
    insp.add_argument("file", type=Path)
    _home(insp)
    insp.set_defaults(handler=cmd_node_inspect, no_db=True)

    rj = nsub.add_parser("run-job", help="выполнить задание с носителя и записать "
                                         "файл результата")
    rj.add_argument("file", type=Path, help="файл задания (.scnjob)")
    rj.add_argument("--out", type=Path, default=None,
                    help="каталог или файл результата (по умолчанию рядом с заданием)")
    rj.add_argument("--confirm-authorized", action="store_true",
                    help="подтверждаю: работы по целям задания разрешены договором")
    rj.add_argument("--allow-empty-reference", action="store_true",
                    help="выполнить, даже если справочники БДУ/NVD на узле пусты "
                         "(результат будет без сопоставления с уязвимостями)")
    _home(rj)
    rj.set_defaults(handler=cmd_node_run_job)

    off = sub.add_parser("offline", help="автономный режим, сторона центра")
    osub = off.add_subparsers(dest="offline_command", required=True, metavar="command")
    ck = osub.add_parser("center-key", help="открытый ключ центра для установки "
                                            "автономных узлов")
    ck.add_argument("--out", type=Path, default=None, help="записать в файл")
    ck.set_defaults(handler=cmd_center_key, no_db=True)


def _err(msg: str):
    from scanner.cli import CliError
    return CliError(msg)


def _load(args) -> on.OfflineNode:
    try:
        return on.OfflineNode.load(args.home or on.default_home())
    except on.OfflineNodeError as e:
        raise _err(str(e)) from e


def cmd_node_init(args: argparse.Namespace, env=None) -> int:
    home = args.home or on.default_home()
    try:
        center = args.center_key.read_text(encoding="utf-8")
    except OSError as e:
        raise _err(f"не прочитан ключ центра {args.center_key}: {e}") from e
    try:
        pub = on.init_node(home, name=args.name, scope=args.scope, center_key=center,
                           force=args.force)
        node = on.OfflineNode.load(home)
    except on.OfflineNodeError as e:
        raise _err(str(e)) from e
    pub_path = home / on.NODE_PUB_FILE
    if args.pub_out:
        try:
            args.pub_out.write_text(pub_path.read_text("utf-8"), encoding="utf-8")
        except OSError as e:
            raise _err(f"не записан {args.pub_out}: {e}") from e
        pub_path = args.pub_out
    print(f"Узел «{node.name}» установлен в {home}")
    print(f"  сети узла: {', '.join(node.scope)}")
    print(f"  ключ центра: {node.center.fingerprint}  ← сверьте с карточкой узла в «Сканерах»")
    print(f"  ключ узла:   {pub.fingerprint}")
    print(f"Перенесите {pub_path} в центр: «Сканеры» → «{node.name}» → "
          "«Загрузить ключ узла». Закрытый ключ (node-keys.json) с узла не выносится.")
    return 0


def cmd_node_show(args: argparse.Namespace, env=None) -> int:
    node = _load(args)
    print(f"Узел «{node.name}» ({node.home})")
    print(f"  сети узла:   {', '.join(node.scope)}")
    print(f"  ключ узла:   {node.public.fingerprint}")
    print(f"  ключ центра: {node.center.fingerprint}")
    jobs = node.journal()
    print(f"  выполнено заданий: {len(jobs)}")
    for j in jobs[-10:]:
        print(f"    {str(j.get('finished_at', ''))[:16]}  прогон {j.get('run_id')}  "
              f"находок {j.get('findings')}  → {j.get('result_file')}")
    return 0


def _print_header(h: dict) -> None:
    print(f"  задание:  {h.get('job_id')}")
    print(f"  прогон:   {h.get('run_id')}")
    print(f"  узел:     {h.get('node_name')}")
    print(f"  модули:   {' '.join(h.get('modules') or [])}")
    print(f"  целей:    {h.get('targets')}, учётных записей: {h.get('credentials')}")
    print(f"  выдано:   {str(h.get('issued_at', ''))[:16]}, "
          f"действует до {str(h.get('expires_at', ''))[:16]} UTC")


def cmd_node_inspect(args: argparse.Namespace, env=None) -> int:
    node = _load(args)
    data = _read(args.file)
    try:
        env_ = node.check_job(data)
    except on.OfflineNodeError as e:
        try:
            print("Заголовок файла:", file=sys.stderr)
            _print_header(of.parse(data, of.FORMAT_JOB).header)
        except of.OfflineFileError:
            pass
        raise _err(f"задание не будет выполнено: {e}") from e
    print("Задание проверено: подпись центра верна, выпущено для этого узла, срок не истёк.")
    _print_header(env_.header)
    try:
        d = on.describe_job(node, env_)
    except on.OfflineNodeError as e:
        raise _err(str(e)) from e
    print(f"  название: {d['run_name'] or '—'}")
    if d["engagement"]:
        print(f"  договор:  {d['engagement']}")
    print(f"  профиль:  {d['rate_profile']}")
    tg = d["targets"]
    print(f"  цели:     {', '.join(tg[:20])}{f' … ещё {len(tg) - 20}' if len(tg) > 20 else ''}")
    print(f"  сети, которые узел реально проверит (задание ∩ сети узла): "
          f"{', '.join(d['allowed_networks']) or 'нет — задание ничего не проверит'}")
    for c in d["credentials"]:
        print(f"  учётка:   «{c.get('credential')}» {c.get('protocol')} {c.get('user')}"
              f"{':' + str(c['port']) if c.get('port') else ''}")
    if d["cred_candidates"]:
        print(f"  проверка паролей: записей в наборах — {d['cred_candidates']}")
    return 0


def _read(path: Path) -> bytes:
    try:
        if path.stat().st_size > of.MAX_FILE_BYTES:
            raise _err(f"{path}: файл слишком большой")
        return path.read_bytes()
    except OSError as e:
        raise _err(f"не прочитан {path}: {e}") from e


def node_registry_local(engine):
    """Модули узла со справочниками из его собственной БД (комплект данных)."""
    from scanner.feeds.advisories.store import SqlAdvisoryStore
    from scanner.feeds.msrc import MsrcStore
    from scanner.feeds.store import SqlReferenceStore
    from scanner.nodes.agent import node_registry
    return node_registry(SqlReferenceStore(engine), SqlAdvisoryStore(engine),
                         MsrcStore(engine))


def cmd_node_run_job(args: argparse.Namespace, env) -> int:
    if not args.confirm_authorized:
        raise _err("задание выполняется только по целям из договора: подтвердите "
                   "флагом --confirm-authorized")
    node = _load(args)
    data = _read(args.file)
    reference = reference_info(env)
    if not (reference["counts"].get("bdu") or reference["counts"].get("nvd")):
        if not args.allow_empty_reference:
            raise _err("на узле не загружены справочники БДУ ФСТЭК и NVD — находки не "
                       "сопоставятся с уязвимостями и результат будет ложно чистым. "
                       "Загрузите комплект данных: scanner bundle import <файл> "
                       "(или добавьте --allow-empty-reference)")
        print("Внимание: справочники БДУ/NVD пусты, сопоставление с уязвимостями "
              "не выполнится", file=sys.stderr)
    print(f"Справочники узла: БДУ {reference['counts'].get('bdu') or 0}, "
          f"NVD {reference['counts'].get('nvd') or 0}, "
          f"на {reference.get('as_of') or 'неизвестную дату'}", file=sys.stderr)

    def progress(snap: dict) -> None:
        stage = snap.get("stage") or ""
        pct = snap.get("percent")
        done, total = snap.get("hosts_done"), snap.get("hosts_total")
        print(f"\r  {stage}: {done}/{total} хостов, {pct}%   ", end="", file=sys.stderr)

    def events(e) -> None:
        msg = getattr(e, "message", None) or str(e)
        subject = getattr(e, "subject", "")
        print(f"\n  [{subject}] {msg}", file=sys.stderr)

    try:
        result, header = on.run_job(node, data, registry=node_registry_local(env.engine),
                                    audit=env.audit, progress=progress, events=events,
                                    version=_version(), reference=reference)
    except on.OfflineNodeError as e:
        raise _err(str(e)) from e
    print(file=sys.stderr)
    out = args.out or args.file.parent
    target = out / on.result_filename(header) if out.is_dir() else out
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_bytes(result)
    tmp.replace(target)
    on.record_done(node, header, str(target))
    print(f"Результат: {target}")
    print(f"  хостов: {header['hosts']}, находок: {header['findings']}"
          + (f", ошибки модулей: {', '.join(header['errors'])}" if header["errors"] else "")
          + (" — прогон остановлен" if header["stopped"] else ""))
    print("Перенесите файл в центр: карточка прогона → «Загрузить результат». "
          "Файл зашифрован на ключ центра, прочитать его на носителе нельзя.")
    return 0


def reference_info(env) -> dict:
    """Сколько записей в справочниках узла и дата самой свежей загрузки."""
    from sqlalchemy import select

    from scanner.core.db import FeedSync, session_scope
    from scanner.feeds.readiness import record_counts
    with session_scope(env.sessions) as s:
        counts = record_counts(s)
        try:
            feeds = {r.source: r.last_success_at.isoformat()
                     for r in s.scalars(select(FeedSync)).all() if r.last_success_at}
        except Exception:  # noqa: BLE001 — нет таблицы в старой схеме
            feeds = {}
    as_of = max(feeds.values())[:10] if feeds else None
    return {"counts": counts, "feeds": feeds, "as_of": as_of}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("scanner")
    except Exception:  # noqa: BLE001
        return ""


def cmd_center_key(args: argparse.Namespace, env=None) -> int:
    from scanner.api.settings import ApiSettings
    from scanner.nodes.offline_center import OfflineError, center_keys, center_material
    try:
        pub = center_keys(center_material(ApiSettings())).public
    except OfflineError as e:
        raise _err(str(e)) from e
    text = (f"# Открытый ключ центра сканера. Отпечаток: {pub.fingerprint}\n"
            f"{pub.export()}\n")
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"Ключ центра записан в {args.out}; отпечаток {pub.fingerprint}")
    else:
        sys.stdout.write(text)
    return 0
