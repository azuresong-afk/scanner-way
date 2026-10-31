"""Канал «Почта» (SMTP). Шифрование соединения — STARTTLS или SSL; вход по паролю
разрешён только по зашифрованному соединению."""
from __future__ import annotations

import re
import smtplib
from email.message import EmailMessage
from typing import Any

from scanner.integrations.base import (
    Channel,
    ChannelConfigError,
    DeliveryError,
    SendResult,
    Transports,
    get_choice,
    get_host,
    get_int,
    opt_str,
    req_str,
)
from scanner.integrations.events import EVENTS, Event
from scanner.integrations.render import render_text

_EMAIL = re.compile(r"^[^@\s<>,;]{1,64}@[^@\s<>,;]{1,255}$")
SECURITY = ("starttls", "ssl", "none")
MAX_RECIPIENTS = 20


class SmtpChannel(Channel):
    type = "smtp"
    title = "Почта (SMTP)"
    supported_events = frozenset(EVENTS)
    secret_fields = ("password",)

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        security = get_choice(config, "security", "Шифрование", "starttls", SECURITY)
        username = opt_str(config, "username", "Логин")
        to = config.get("to")
        if isinstance(to, str):
            to = [x for x in re.split(r"[,;\s]+", to) if x]
        if not isinstance(to, list) or not to or len(to) > MAX_RECIPIENTS \
                or not all(isinstance(x, str) and _EMAIL.match(x.strip()) for x in to):
            raise ChannelConfigError(f"«Кому»: от 1 до {MAX_RECIPIENTS} адресов электронной почты")
        sender = req_str(config, "sender", "От кого")
        if not _EMAIL.match(sender):
            raise ChannelConfigError("«От кого»: нужен адрес электронной почты")
        if username and security == "none":
            raise ChannelConfigError("вход по паролю без шифрования соединения запрещён: "
                                     "выберите STARTTLS или SSL")
        default_port = 465 if security == "ssl" else 587 if security == "starttls" else 25
        return {"host": get_host(config), "port": get_int(config, "port", "Порт",
                                                          default_port, 1, 65535),
                "security": security, "username": username, "sender": sender,
                "to": [x.strip() for x in to]}

    def validate_secrets(self, secrets, config):
        if config.get("username") and not secrets.get("password"):
            raise ChannelConfigError("для входа задан логин — укажите пароль")

    def send(self, event: Event, config, secrets, tx: Transports) -> SendResult:
        subject, body = render_text(event)
        msg = EmailMessage()
        msg["Subject"] = " ".join(subject.split())[:200]
        msg["From"], msg["To"] = config["sender"], ", ".join(config["to"])
        msg.set_content(body)
        use_ssl = config["security"] == "ssl"
        try:
            with tx.smtp_factory(config["host"], config["port"], use_ssl, 20.0) as smtp:
                if config["security"] == "starttls":
                    import ssl
                    smtp.starttls(context=ssl.create_default_context())
                if config.get("username"):
                    smtp.login(config["username"], secrets.get("password", ""))
                smtp.send_message(msg)
        except smtplib.SMTPAuthenticationError:
            raise DeliveryError("SMTP: неверный логин или пароль", retry=False) from None
        except smtplib.SMTPRecipientsRefused:
            raise DeliveryError("SMTP: получатели отклонены сервером", retry=False) from None
        except (smtplib.SMTPException, OSError) as e:
            raise DeliveryError(f"SMTP: {type(e).__name__}") from None
        return SendResult(note=f"получателей: {len(config['to'])}")
