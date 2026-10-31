"""Канал Jira (REST API v2): задача на каждую новую критичную находку.

Дедуп: ключ находки (договор + dedup_key) — ключ дедупа доставки, диспетчер не
создаёт вторую задачу на ту же находку, пока первая доставка жива (в очереди или
выполнена). Повтор после сбоя идемпотентен: на каждую находку — своя доставка.
В описание задачи попадают хост, порт, идентификаторы и ссылка на отчёт — без
доказательств находки.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from typing import Any

from scanner.integrations.base import (
    Channel,
    ChannelConfigError,
    Delivery,
    DeliveryError,
    SendResult,
    Transports,
    get_choice,
    get_int,
    get_url,
    http_failure,
    opt_str,
    req_str,
)
from scanner.integrations.events import NEW_CRITICAL, TEST, Event, Item
from scanner.integrations.render import PRIORITY_RU, SEVERITY_ONE

_PROJECT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,19}$")
_LABEL = re.compile(r"^[A-Za-z0-9_.\-]{1,50}$")
AUTH_TYPES = ("basic", "bearer")
DEFAULT_MAX_ISSUES = 20


def finding_ref(engagement_id: int | None, dedup_key: str) -> str:
    return hashlib.sha256(f"{engagement_id}|{dedup_key}".encode()).hexdigest()[:16]


class JiraChannel(Channel):
    type = "jira"
    title = "Jira"
    supported_events = frozenset({NEW_CRITICAL})
    secret_fields = ("api_token",)
    required_secrets = ("api_token",)

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        auth = get_choice(config, "auth_type", "Тип входа", "basic", AUTH_TYPES)
        project = req_str(config, "project_key", "Ключ проекта", maxlen=20).upper()
        if not _PROJECT.match(project):
            raise ChannelConfigError("«Ключ проекта»: латиница/цифры, например SEC")
        labels = config.get("labels") or []
        if isinstance(labels, str):
            labels = [x for x in re.split(r"[,\s]+", labels) if x]
        if not isinstance(labels, list) or len(labels) > 10 \
                or not all(isinstance(x, str) and _LABEL.match(x) for x in labels):
            raise ChannelConfigError("«Метки»: до 10 меток без пробелов")
        username = opt_str(config, "username", "Логин (email)")
        if auth == "basic" and not username:
            raise ChannelConfigError("«Логин (email)» обязателен для входа по токену API")
        return {"base_url": get_url(config, "base_url", "Адрес Jira"),
                "project_key": project,
                "issue_type": opt_str(config, "issue_type", "Тип задачи", "Task", maxlen=60),
                "auth_type": auth, "username": username, "labels": labels,
                "max_issues": get_int(config, "max_issues", "Задач за событие",
                                      DEFAULT_MAX_ISSUES, 1, 100)}

    def deliveries(self, event: Event, config: dict[str, Any]) -> list[Delivery]:
        cap = config.get("max_issues", DEFAULT_MAX_ISSUES)
        return [Delivery(replace(event, items=[i], items_omitted=0),
                         dedup_key=f"jira:{event.engagement_id}:{i.dedup_key}")
                for i in event.items[:cap]]

    # ---- HTTP ----
    @staticmethod
    def _auth(config, secrets) -> tuple[dict[str, str], tuple[str, str] | None]:
        h = {"Accept": "application/json"}
        if config["auth_type"] == "bearer":
            h["Authorization"] = f"Bearer {secrets['api_token']}"
            return h, None
        return h, (config["username"], secrets["api_token"])

    def _check_login(self, config, secrets, tx: Transports) -> SendResult:
        headers, auth = self._auth(config, secrets)
        resp = tx.http.request("GET", f"{config['base_url']}/rest/api/2/myself",
                               headers=headers, auth=auth)
        if resp.status != 200:
            raise http_failure(resp, "Jira: проверка входа")
        name = resp.body.get("displayName") if isinstance(resp.body, dict) else None
        return SendResult(note=f"вход выполнен{': ' + str(name) if name else ''}")

    def send(self, event: Event, config, secrets, tx: Transports) -> SendResult:
        if event.kind == TEST:
            return self._check_login(config, secrets, tx)
        item = event.items[0]
        headers, auth = self._auth(config, secrets)
        label = f"scanner-{finding_ref(event.engagement_id, item.dedup_key)}"
        fields = {"project": {"key": config["project_key"]},
                  "issuetype": {"name": config["issue_type"]},
                  "summary": _summary(item),
                  "description": _description(event, item),
                  "labels": ["scanner", label, *config.get("labels", [])]}
        resp = tx.http.request("POST", f"{config['base_url']}/rest/api/2/issue",
                               headers=headers, auth=auth, json={"fields": fields})
        if resp.status not in (200, 201) or not isinstance(resp.body, dict):
            err = http_failure(resp, "Jira: создание задачи")
            msgs = resp.body.get("errorMessages") if isinstance(resp.body, dict) else None
            raise DeliveryError(f"{err}" + (f" — {'; '.join(map(str, msgs))[:200]}"
                                            if msgs else ""), retry=err.retry)
        return SendResult(external_ref=str(resp.body.get("key") or ""))


def _summary(i: Item) -> str:
    where = f"{i.host}:{i.port}" if i.port else i.host
    return " ".join(f"[Scanner] {i.title} — {where}".split())[:250]


def _description(ev: Event, i: Item) -> str:
    rows = [f"Хост: {i.host}" + (f":{i.port}" if i.port else ""),
            f"Уровень опасности: {SEVERITY_ONE.get(i.severity, i.severity)}"]
    if i.priority:
        rows.append(f"Приоритет: {PRIORITY_RU.get(i.priority, i.priority)}"
                    + (f" ({i.score:g})" if i.score is not None else ""))
    if i.in_kev:
        rows.append("Эксплуатируется в реальных атаках (CISA KEV)")
    ids = [x for x in ([i.vuln_id] if i.vuln_id else []) + list(i.cve_ids) + list(i.bdu_ids)]
    if ids:
        rows.append("Идентификаторы: " + ", ".join(dict.fromkeys(ids)))
    rows.append(f"Статус в прогоне: {'повторное появление' if i.status == 'regression' else 'новая'}")
    if ev.engagement_name:
        rows.append(f"Договор: {ev.engagement_name}")
    if ev.link:
        rows.append(f"Отчёт сканера: {ev.link}")
    return "\n".join(rows)
