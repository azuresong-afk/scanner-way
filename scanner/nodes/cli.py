"""Команды `scanner node …` (узел-сканер).

Подкоманды с ``no_db=True`` работают без БД (на узле её нет): обработчик
получает ``env=None``. Подкоманды, которым нужна БД центра, ставят
``no_db=False`` и получают обычное окружение CLI.
"""
from __future__ import annotations

import argparse
from typing import Any


def add_node_commands(sub: Any) -> argparse.ArgumentParser:
    node = sub.add_parser("node", help="узел-сканер в изолированном сегменте "
                                       "(без интерфейса и БД)")
    nsub = node.add_subparsers(dest="node_command", required=True, metavar="action")
    nrun = nsub.add_parser("run", help="агент сетевого узла: подключиться к центру и "
                                       "выполнять задания (параметры — SCANNER_NODE_*)")
    nrun.add_argument("--once", action="store_true",
                      help="забрать и выполнить не больше одного задания и выйти")
    nrun.set_defaults(handler=cmd_node_run, no_db=True)
    ncheck = nsub.add_parser("check", help="проверить настройки узла и связь с центром")
    ncheck.set_defaults(handler=cmd_node_check, no_db=True)
    node.set_defaults(node_subparsers=nsub)
    return node


def _node_agent():
    from scanner.cli import CliError
    from scanner.nodes.agent import NodeAgent, NodeConfigError, config_from_env
    from scanner.nodes.remote import NodeClient
    try:
        cfg = config_from_env()
        client = NodeClient(cfg.server, cfg.token, ca=cfg.ca, client_cert=cfg.client_cert,
                            client_key=cfg.client_key, allow_http=cfg.allow_http)
    except (NodeConfigError, ValueError, OSError) as e:
        raise CliError(str(e)) from e
    return NodeAgent(client, cfg)


def cmd_node_check(args: argparse.Namespace, env: Any) -> int:
    from scanner.cli import CliError
    from scanner.nodes.agent import node_info
    from scanner.nodes.remote import NodeApiError
    agent = _node_agent()
    info = node_info(agent.cfg)
    print(f"Центр: {agent.cfg.server}")
    print(f"Локальный allowlist узла: {', '.join(agent.cfg.allowlist)}")
    print("Инструменты: " + ", ".join(f"{k} {'есть' if v else 'НЕТ'}"
                                      for k, v in info["tools"].items()))
    try:
        res = agent.hello()
    except NodeApiError as e:
        raise CliError(f"связь с центром не установлена: {e}") from e
    node = res.get("node") or {}
    print(f"Связь с центром: OK, узел «{node.get('name')}» (id {node.get('id')})")
    print(f"Сети узла в центре: {', '.join(node.get('scope') or []) or '—'}")
    outside = res.get("outside_local_allowlist") or []
    if outside:
        print("ВНИМАНИЕ: эти сети узла в центре вне локального allowlist и проверяться "
              f"не будут: {', '.join(outside)}")
    return 0


def cmd_node_run(args: argparse.Namespace, env: Any) -> int:
    import logging
    import signal
    import threading
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)   # опрос раз в несколько секунд
    agent = _node_agent()
    if args.once:
        agent.hello()
        agent.resend_spooled()
        agent.run_once()
        return 0
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    agent.run_forever(stop)
    return 0
