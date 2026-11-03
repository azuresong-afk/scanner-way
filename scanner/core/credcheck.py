"""Проверка входа по учётной записи актива — без сканирования.

Для каждого хоста берутся привязанные к нему учётки договора (область действия
учётки покрывает адрес хоста или пуста — см. `credentials_for_host`), и по
каждой делается ровно одна попытка входа:

  * SSH — TCP-подключение к порту учётки, затем вход paramiko (`sshexec.connect`)
    и сразу закрытие сессии. Ни одной команды на хосте не выполняется;
  * WinRM — TCP-подключение, затем открытие и закрытие оболочки WS-Man
    (`winexec.connect`: именно здесь проходят TLS и NTLM). Ни одного скрипта.

Перед входом — быстрая TCP-проба порта учётки (`reachability.tcp_probe`):
закрытый порт и молчащий хост дают понятный ответ за секунды, без ожидания
полного таймаута SSH/WinRM.

Исход каждой попытки — один из `STATUSES` с пояснением на русском. Тексты
пояснений строятся сканером, секреты в них не попадают (исключения `sshexec`
и `winexec` уже очищены от учётных данных).

Защита от блокировки учётных записей на цели: каждая учётка пробуется один раз,
на хост — не больше `MAX_CREDENTIALS_PER_HOST` учёток каждого протокола (как в
прогоне). Allowlist, права и частоту проверяет вызывающий (`routes_credcheck`).
"""
from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from scanner.core import sshexec, winexec
from scanner.core.credentials import (
    PROTOCOL_SSH,
    PROTOCOL_WINRM,
    PROTOCOLS,
    CredentialError,
    HostCredential,
    credentials_for_host,
)
from scanner.core.reachability import PortResult, tcp_probe

OK = "ok"
AUTH_FAILED = "auth_failed"
TIMEOUT = "timeout"
UNREACHABLE = "unreachable"
HOST_KEY_MISMATCH = "host_key_mismatch"
NO_CREDENTIAL = "no_credential"
NOT_IN_ALLOWLIST = "not_in_allowlist"
ERROR = "error"
STATUSES = (OK, AUTH_FAILED, TIMEOUT, UNREACHABLE, HOST_KEY_MISMATCH,
            NO_CREDENTIAL, NOT_IN_ALLOWLIST, ERROR)
# Итог по хосту, если часть учёток вошла, а часть — нет.
PARTIAL = "partial"

PRECHECK_TIMEOUT_SEC = 3.0
LOGIN_TIMEOUT_SEC = 10.0

Probe = Callable[[str, int, float], PortResult]
SshConnect = Callable[[str, HostCredential, sshexec.SshOptions], sshexec.RemoteShell]
WinConnect = Callable[[str, HostCredential, winexec.WinRmOptions], winexec.WinShell]


@dataclass(slots=True)
class LoginResult:
    """Исход одной попытки входа. Без секретов — только метаданные учётки."""
    credential_id: int
    credential: str
    protocol: str
    username: str
    port: int
    status: str
    message: str
    elapsed_ms: float = 0.0


@dataclass(slots=True)
class HostCheck:
    host: str
    status: str                         # из STATUSES или PARTIAL
    message: str
    results: list[LoginResult] = field(default_factory=list)
    elapsed_ms: float = 0.0


@dataclass(slots=True)
class Connectors:
    """Чем подключаться — подменяется в тестах."""
    ssh_options: sshexec.SshOptions
    win_options: winexec.WinRmOptions
    probe: Probe = tcp_probe
    ssh_connect: SshConnect = sshexec.connect
    win_connect: WinConnect = winexec.connect
    precheck_timeout: float = PRECHECK_TIMEOUT_SEC


def default_connectors(login_timeout: float = LOGIN_TIMEOUT_SEC) -> Connectors:
    """Настройки known_hosts/сертификатов — те же, что у прогона (из окружения);
    таймаут входа короче прогонного: проверка интерактивная."""
    ssh = sshexec.options_from_env()
    ssh.connect_timeout_sec = min(ssh.connect_timeout_sec, login_timeout)
    win = winexec.options_from_env()
    win.connect_timeout_sec = min(win.connect_timeout_sec, login_timeout)
    win.operation_timeout_sec = max(1, int(min(win.operation_timeout_sec, login_timeout)))
    return Connectors(ssh_options=ssh, win_options=win)


def _timed_out(e: BaseException) -> bool:
    """Причина — таймаут (сокет, баннер SSH, чтение HTTP)?"""
    seen: BaseException | None = e
    while seen is not None:
        if isinstance(seen, TimeoutError):
            return True
        name = type(seen).__name__.lower()
        text = str(seen).lower()
        if "timeout" in name or "timed out" in text or "banner" in text:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _login_ssh(host: str, cred: HostCredential, c: Connectors) -> tuple[str, str]:
    try:
        shell = c.ssh_connect(host, cred, c.ssh_options)
    except sshexec.AuthFailed:
        return AUTH_FAILED, "SSH: логин или пароль/ключ отклонены хостом"
    except sshexec.HostKeyMismatch as e:
        return HOST_KEY_MISMATCH, f"SSH: {e}"
    except sshexec.Unreachable as e:
        if _timed_out(e):
            return TIMEOUT, (f"SSH: порт {cred.port} не ответил за "
                             f"{c.ssh_options.connect_timeout_sec:.0f} с")
        return UNREACHABLE, f"SSH: нет соединения с портом {cred.port}"
    except CredentialError as e:
        return ERROR, f"учётная запись: {e}"
    except sshexec.SshError as e:
        if _timed_out(e):
            return TIMEOUT, (f"SSH: сервер не ответил за "
                             f"{c.ssh_options.connect_timeout_sec:.0f} с")
        return ERROR, f"SSH: {str(e)[:200]}"
    shell.close()
    return OK, "SSH: вход выполнен"


def _login_winrm(host: str, cred: HostCredential, c: Connectors) -> tuple[str, str]:
    try:
        shell = c.win_connect(host, cred, c.win_options)
    except winexec.AuthFailed:
        return AUTH_FAILED, "WinRM: логин или пароль отклонены хостом"
    except winexec.CertMismatch as e:
        return HOST_KEY_MISMATCH, f"WinRM: {e}"
    except winexec.Unreachable as e:
        if _timed_out(e):
            return TIMEOUT, (f"WinRM: порт {cred.port} не ответил за "
                             f"{c.win_options.connect_timeout_sec:.0f} с")
        return UNREACHABLE, f"WinRM: нет соединения с портом {cred.port}"
    except winexec.WinRmError as e:
        if _timed_out(e):
            return TIMEOUT, "WinRM: сервер не ответил вовремя"
        return ERROR, f"WinRM: {str(e)[:200]}"
    shell.close()
    return OK, "WinRM: вход выполнен"


def check_login(host: str, cred: HostCredential, c: Connectors) -> LoginResult:
    """Одна попытка входа по учётке: TCP-проба порта, затем вход и выход."""
    start = time.monotonic()
    label = "SSH" if cred.protocol == PROTOCOL_SSH else "WinRM"
    pre = c.probe(host, cred.port, c.precheck_timeout)
    if pre.state == "closed":
        status, message = UNREACHABLE, f"{label}: порт {cred.port} закрыт"
    elif pre.state != "open":
        status, message = TIMEOUT, (f"{label}: порт {cred.port} не ответил за "
                                    f"{c.precheck_timeout:.0f} с — хост выключен "
                                    "или порт закрыт межсетевым экраном")
    elif cred.protocol == PROTOCOL_WINRM:
        status, message = _login_winrm(host, cred, c)
    else:
        status, message = _login_ssh(host, cred, c)
    return LoginResult(credential_id=cred.id, credential=cred.name,
                       protocol=cred.protocol, username=cred.username, port=cred.port,
                       status=status, message=message,
                       elapsed_ms=round((time.monotonic() - start) * 1000, 1))


def bound_credentials(host: str, creds: Sequence[HostCredential]) -> list[HostCredential]:
    """Учётки, привязанные к хосту: по каждому протоколу — как их выберет прогон."""
    out: list[HostCredential] = []
    for proto in PROTOCOLS:
        out.extend(credentials_for_host(host, creds, protocol=proto))
    return out


def summarize(host: str, results: list[LoginResult], elapsed_ms: float) -> HostCheck:
    if not results:
        return HostCheck(host, NO_CREDENTIAL,
                         "к хосту не привязана ни одна учётная запись: область "
                         "действия учёток договора не покрывает этот адрес",
                         [], elapsed_ms)
    ok = [r for r in results if r.status == OK]
    if len(ok) == len(results):
        msg = "вход выполнен" if len(ok) == 1 else f"вход выполнен по всем {len(ok)} учёткам"
        return HostCheck(host, OK, msg, results, elapsed_ms)
    if ok:
        return HostCheck(host, PARTIAL,
                         f"вход выполнен по {len(ok)} из {len(results)} учёток",
                         results, elapsed_ms)
    first = results[0]
    return HostCheck(host, first.status, first.message, results, elapsed_ms)


def check_host_credentials(host: str, creds: Sequence[HostCredential],
                           c: Connectors) -> HostCheck:
    """Все привязанные к хосту учётки — по очереди (не параллельно: одна цель)."""
    start = time.monotonic()
    results = [check_login(host, cred, c) for cred in bound_credentials(host, creds)]
    return summarize(host, results, round((time.monotonic() - start) * 1000, 1))
