"""Канал «Syslog (CEF)»: события в SIEM по RFC 5424, тело — ArcSight CEF.

Один CEF-пакет на событие; для «новых критичных» — по пакету на находку. Передача —
UDP либо TCP (без шифрования: сервер syslog внутри контура, прокси не используется).
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from scanner.integrations.base import (
    Channel,
    ChannelConfigError,
    SendResult,
    Transports,
    get_choice,
    get_host,
    get_int,
    opt_str,
)
from scanner.integrations.events import (
    EVENTS,
    FEED_STALE,
    NEW_CRITICAL,
    RUN_FINISHED,
    Event,
    Item,
)

FACILITIES = {"user": 1, "auth": 4, "authpriv": 10,
              **{f"local{i}": 16 + i for i in range(8)}}
# уровень опасности → (CEF severity 0–10, syslog severity)
SEVERITY_MAP = {"critical": (10, 2), "high": (8, 3), "medium": (5, 4), "low": (3, 5),
                "info": (1, 6)}
MAX_MESSAGES = 100
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def cef_header(value: str) -> str:
    return _CTRL.sub(" ", str(value)).replace("\\", "\\\\").replace("|", "\\|")


def cef_ext(value: object) -> str:
    s = str(value).replace("\\", "\\\\").replace("=", "\\=")
    return _CTRL.sub(" ", s.replace("\r\n", "\n").replace("\n", "\\n"))


def cef_line(signature: str, name: str, severity: int, ext: dict[str, object]) -> str:
    body = " ".join(f"{k}={cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    return (f"CEF:0|Scanner|Scanner|1.0|{cef_header(signature)}|{cef_header(name)}|"
            f"{severity}|{body}")


def syslog_frame(pri: int, hostname: str, app: str, msgid: str, msg: str,
                 ts: datetime | None = None) -> str:
    stamp = (ts or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    host = re.sub(r"[^\x21-\x7e]", "-", hostname)[:255] or "-"
    return f"<{pri}>1 {stamp} {host} {app} - {msgid} - {msg}"


class SyslogCefChannel(Channel):
    type = "syslog_cef"
    title = "Syslog (CEF)"
    supported_events = frozenset(EVENTS)

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        fac = get_choice(config, "facility", "Facility", "local4", tuple(FACILITIES))
        proto = get_choice(config, "protocol", "Протокол", "udp", ("udp", "tcp"))
        if not re.fullmatch(r"[\x21-\x7e]{1,48}", opt_str(config, "app_name", "Имя приложения",
                                                          "scanner")):
            raise ChannelConfigError("«Имя приложения»: латиница/цифры без пробелов")
        return {"host": get_host(config), "port": get_int(config, "port", "Порт", 514, 1, 65535),
                "protocol": proto, "facility": fac,
                "app_name": opt_str(config, "app_name", "Имя приложения", "scanner")}

    def _packets(self, ev: Event) -> list[tuple[str, int]]:
        """[(CEF, syslog severity)]."""
        base = {"cn1Label": "scanRunId", "cn1": ev.scan_run_id,
                "cs4Label": "engagement", "cs4": ev.engagement_name,
                "request": ev.link}
        if ev.kind == NEW_CRITICAL:
            return [(self._finding(ev, i, base), SEVERITY_MAP.get(i.severity, (5, 4))[1])
                    for i in ev.items[:MAX_MESSAGES]]
        if ev.kind == RUN_FINISHED:
            c = ev.counts
            sev = (7 if c.get("critical") else 5 if c.get("high") else 3 if c.get("medium")
                   else 1)
            ext = {**base, "msg": f"hosts={ev.hosts_total} findings={sum(c.values())} "
                                  f"new={ev.new_total} status={ev.run_status}",
                   "cn2Label": "findingsCritical", "cn2": c.get("critical", 0),
                   "cn3Label": "findingsNew", "cn3": ev.new_total}
            return [(cef_line("run_finished", "Scan run finished", sev, ext), 6)]
        if ev.kind == FEED_STALE:
            return [(cef_line("feed_stale", "Reference feed not updated", 5,
                              {"msg": f"{ev.title}: {ev.message or ''}"[:500],
                               "cs4Label": "feed", "cs4": ev.source}), 4)]
        return [(cef_line("test", "Scanner test notification", 1, {"msg": ev.message}), 6)]

    @staticmethod
    def _finding(ev: Event, i: Item, base: dict) -> str:
        cef_sev = SEVERITY_MAP.get(i.severity, (5, 4))[0]
        ext = {**base, "src": i.host, "dpt": i.port, "msg": i.title[:500],
               "externalId": i.dedup_key[:32],
               "cs1Label": "vulnId", "cs1": i.vuln_id,
               "cs2Label": "bduIds", "cs2": ",".join(i.bdu_ids),
               "cs3Label": "priority", "cs3": i.priority,
               "cn2Label": "priorityScore", "cn2": None if i.score is None else int(i.score),
               "cs5Label": "findingStatus", "cs5": i.status}
        return cef_line("new_critical", i.title[:120], cef_sev, ext)

    def send(self, event: Event, config, secrets, tx: Transports) -> SendResult:
        n = 0
        for cef, sev in self._packets(event):
            pri = FACILITIES[config["facility"]] * 8 + sev
            line = syslog_frame(pri, tx.hostname, config["app_name"], event.kind, cef)
            data = (line + ("\n" if config["protocol"] == "tcp" else "")).encode()
            tx.syslog_send(config["host"], config["port"], config["protocol"], data)
            n += 1
        return SendResult(note=f"сообщений: {n}")
