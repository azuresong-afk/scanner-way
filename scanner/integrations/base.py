"""Общее для каналов: ошибки, транспорты (подменяются в тестах), валидация."""
from __future__ import annotations

import re
import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from scanner.integrations.events import Event

HTTP_TIMEOUT = 15.0
TRANSIENT_STATUSES = frozenset({408, 425, 429})


class ChannelConfigError(ValueError):
    """Недопустимая конфигурация канала (текст показывается оператору)."""


class DeliveryError(Exception):
    """Не удалось доставить. retry=False — повтор бесполезен (неверные параметры)."""

    def __init__(self, message: str, *, retry: bool = True):
        super().__init__(message)
        self.retry = retry


@dataclass(slots=True)
class SendResult:
    external_ref: str | None = None      # например, ключ задачи Jira
    note: str | None = None


@dataclass(slots=True)
class Delivery:
    """Одна доставка: событие (возможно, урезанное под канал) и ключ дедупа."""
    event: Event
    dedup_key: str | None = None
    dedup_window: timedelta | None = None     # None — навсегда


# ---------- HTTP ----------

@dataclass(slots=True)
class HttpResponse:
    status: int
    body: Any                  # разобранный JSON либо текст


class HttpClient(Protocol):
    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, params: dict[str, str] | None = None,
                auth: tuple[str, str] | None = None) -> HttpResponse: ...


class HttpxClient:
    """HTTP(S) через httpx: системный прокси (HTTPS_PROXY/NO_PROXY) учитывается.
    Текст сетевых ошибок не содержит URL: в нём бывает токен бота."""

    def __init__(self, timeout: float = HTTP_TIMEOUT):
        self.timeout = timeout

    def request(self, method, url, *, headers=None, json=None, params=None, auth=None):
        try:
            with httpx.Client(timeout=self.timeout, trust_env=True,
                              follow_redirects=False) as c:
                r = c.request(method, url, headers=headers, json=json, params=params,
                              auth=auth)
        except httpx.HTTPError as e:
            raise DeliveryError(f"сетевая ошибка: {type(e).__name__}") from None
        try:
            body: Any = r.json()
        except ValueError:
            body = r.text[:500]
        return HttpResponse(r.status_code, body)


def http_failure(resp: HttpResponse, what: str) -> DeliveryError:
    """Ошибка по коду ответа: 5xx/429/408 — повторить, прочие 4xx — нет."""
    retry = resp.status >= 500 or resp.status in TRANSIENT_STATUSES
    return DeliveryError(f"{what}: HTTP {resp.status}", retry=retry)


# ---------- SMTP / syslog ----------

SmtpFactory = Any      # (host, port, use_ssl, timeout) -> объект в стиле smtplib.SMTP
SyslogSender = Any     # (host, port, protocol, data: bytes) -> None


def default_smtp_factory(host: str, port: int, use_ssl: bool, timeout: float):
    if use_ssl:
        return smtplib.SMTP_SSL(host, port, timeout=timeout,
                                context=ssl.create_default_context())
    return smtplib.SMTP(host, port, timeout=timeout)


def default_syslog_sender(host: str, port: int, protocol: str, data: bytes) -> None:
    try:
        if protocol == "udp":
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                               socket.SOCK_DGRAM) as s:
                s.settimeout(HTTP_TIMEOUT)
                s.sendto(data, (host, port))
        else:
            with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as s:
                s.sendall(data)
    except OSError as e:
        raise DeliveryError(f"syslog: {type(e).__name__}") from None


@dataclass(slots=True)
class Transports:
    """Сетевые транспорты каналов; в тестах заменяются фейками."""
    http: HttpClient = field(default_factory=HttpxClient)
    smtp_factory: SmtpFactory = default_smtp_factory
    syslog_send: SyslogSender = default_syslog_sender
    hostname: str = field(default_factory=lambda: socket.gethostname() or "scanner")


# ---------- канал ----------

class Channel:
    type = ""
    title = ""
    supported_events: frozenset[str] = frozenset()
    secret_fields: tuple[str, ...] = ()
    required_secrets: tuple[str, ...] = ()

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        """Проверяет и нормализует открытую конфигурацию."""
        raise NotImplementedError

    def validate_secrets(self, secrets: dict[str, str], config: dict[str, Any]) -> None:
        for name in self.required_secrets:
            if not secrets.get(name):
                raise ChannelConfigError(f"не задан секрет «{name}»")

    def deliveries(self, event: Event, config: dict[str, Any]) -> list[Delivery]:
        return [Delivery(event)]

    def send(self, event: Event, config: dict[str, Any], secrets: dict[str, str],
             tx: Transports) -> SendResult:
        raise NotImplementedError


# ---------- валидация полей ----------

def req_str(cfg: dict, key: str, label: str, *, maxlen: int = 200) -> str:
    v = cfg.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ChannelConfigError(f"«{label}» обязательно")
    v = v.strip()
    if len(v) > maxlen or any(ord(c) < 32 for c in v):
        raise ChannelConfigError(f"«{label}» недопустимо")
    return v


def opt_str(cfg: dict, key: str, label: str, default: str = "", *, maxlen: int = 200) -> str:
    v = cfg.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        return default
    return req_str(cfg, key, label, maxlen=maxlen)


def get_int(cfg: dict, key: str, label: str, default: int, lo: int, hi: int) -> int:
    v = cfg.get(key)
    if v is None or v == "":
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ChannelConfigError(f"«{label}» должно быть числом") from None
    if not lo <= n <= hi:
        raise ChannelConfigError(f"«{label}» — от {lo} до {hi}")
    return n


def get_choice(cfg: dict, key: str, label: str, default: str, choices: tuple[str, ...]) -> str:
    v = cfg.get(key) or default
    if v not in choices:
        raise ChannelConfigError(f"«{label}» — одно из: {', '.join(choices)}")
    return v


def get_host(cfg: dict, key: str = "host", label: str = "Сервер") -> str:
    v = req_str(cfg, key, label, maxlen=253)
    if not re.fullmatch(r"[A-Za-z0-9._:\-\[\]]+", v):
        raise ChannelConfigError(f"«{label}»: допустимы имя хоста или IP-адрес")
    return v


def get_url(cfg: dict, key: str, label: str, default: str = "") -> str:
    v = opt_str(cfg, key, label, default, maxlen=300).rstrip("/")
    u = urlsplit(v)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ChannelConfigError(f"«{label}»: нужен адрес http(s)://хост без логина и пароля")
    return v
