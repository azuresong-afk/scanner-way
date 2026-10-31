"""Канал Telegram (Bot API, sendMessage). Токен бота — секрет; в URL он есть, поэтому
тексты ошибок транспорта URL не содержат."""
from __future__ import annotations

import re
from typing import Any

from scanner.integrations.base import (
    Channel,
    ChannelConfigError,
    DeliveryError,
    SendResult,
    Transports,
    get_url,
    http_failure,
)
from scanner.integrations.events import EVENTS, Event
from scanner.integrations.render import render_text

DEFAULT_API = "https://api.telegram.org"
LIMIT = 4000          # у Telegram предел 4096 символов


class TelegramChannel(Channel):
    type = "telegram"
    title = "Telegram"
    supported_events = frozenset(EVENTS)
    secret_fields = ("bot_token",)
    required_secrets = ("bot_token",)

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        chat = str(config.get("chat_id", "")).strip()
        if not re.fullmatch(r"-?\d{1,20}|@[A-Za-z0-9_]{4,64}", chat):
            raise ChannelConfigError("«Чат»: числовой id чата или @имя канала")
        return {"chat_id": chat, "api_base": get_url(config, "api_base", "Адрес Bot API",
                                                     DEFAULT_API)}

    def validate_secrets(self, secrets, config):
        super().validate_secrets(secrets, config)
        tok = secrets["bot_token"]
        if not re.fullmatch(r"[0-9]{3,}:[^\s/]{10,}", tok):
            raise ChannelConfigError("«Токен бота» выглядит неверно (формат 123456:ABC…)")

    def send(self, event: Event, config, secrets, tx: Transports) -> SendResult:
        subject, body = render_text(event)
        text = (subject + "\n\n" + body)[:LIMIT]
        resp = tx.http.request(
            "POST", f"{config['api_base']}/bot{secrets['bot_token']}/sendMessage",
            json={"chat_id": config["chat_id"], "text": text,
                  "disable_web_page_preview": True})
        if resp.status != 200 or not (isinstance(resp.body, dict) and resp.body.get("ok")):
            err = http_failure(resp, "Telegram")
            desc = resp.body.get("description") if isinstance(resp.body, dict) else None
            raise DeliveryError(f"{err}" + (f" — {str(desc)[:150]}" if desc else ""),
                                retry=err.retry)
        return SendResult()
