"""Реестр типов каналов."""
from __future__ import annotations

from scanner.integrations.base import Channel
from scanner.integrations.jira import JiraChannel
from scanner.integrations.smtp import SmtpChannel
from scanner.integrations.syslog_cef import SyslogCefChannel
from scanner.integrations.telegram import TelegramChannel

CHANNELS: dict[str, Channel] = {c.type: c for c in
                                (SmtpChannel(), TelegramChannel(), SyslogCefChannel(),
                                 JiraChannel())}


def get_channel(kind: str) -> Channel:
    try:
        return CHANNELS[kind]
    except KeyError:
        raise KeyError(f"unknown channel type: {kind}") from None
