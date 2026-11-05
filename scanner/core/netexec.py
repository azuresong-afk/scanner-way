"""Доступ к сетевому оборудованию: SSH в CLI устройства и SNMP только чтение.

Используется модулем `netdev_audit` и проверкой входа (`core.credcheck`).

SSH (учётка ``netssh``). Подключение, проверка ключа хоста (TOFU/строгий
режим), предварительная проверка порта и повтор при таймауте — те же, что у
серверов (`core.sshexec.connect`). Отличие — работа с CLI: у коммутаторов и
маршрутизаторов нет обычной оболочки, поэтому команды идут в интерактивный
канал (`invoke_shell`), а конец вывода определяется по приглашению CLI
(``sw1#``, ``<HUAWEI>``, ``user@mx>``). У MikroTik RouterOS (баннер ``ROSSSH``)
интерактивная консоль рисует терминал — для него команды идут через exec, как
на серверах. Пейджинг вывода отключается командой сессии (``terminal length 0``
и аналоги); если устройство всё-таки показало ``--More--``, отправляется пробел.

Какие команды выполнять, решает вызывающий: `netdev_audit` берёт их только из
фиксированного списка просмотра (`modules.netdev.platforms`), ничего из ввода
цели или оператора в команды не попадает.

SNMP (учётка ``snmp``). Один запрос GET на заданные OID (системная группа MIB-2
и OID версии вендора), SNMPv2c (community) или SNMPv3 USM (authPriv / authNoPriv).
Секреты берутся из памяти процесса и не попадают в журнал и исключения.
Неверный community в v2c неотличим от недоступного хоста: агент молчит.

Вывод устройств — недоверенный: лимит размера, управляющие последовательности
терминала вырезаются.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Protocol

from scanner.core import sshexec
from scanner.core.credentials import HostCredential

MAX_OUTPUT_BYTES = 8 * 1024 * 1024

# ---------- общие ошибки ----------


class NetError(RuntimeError):
    """Не удалось получить данные с устройства."""


class SnmpError(NetError):
    """Ошибка SNMP (ответ агента с ошибкой, неверный запрос)."""


class SnmpAuthFailed(SnmpError):
    """SNMPv3: неверный логин или ключи (агент ответил отчётом USM)."""


class SnmpTimeout(SnmpError):
    """Агент SNMP не ответил: хост недоступен, UDP/161 закрыт, неверный
    community (v2c) или адрес сканера не разрешён на устройстве."""


# ---------- SSH-CLI ----------

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\r")
_MORE = re.compile(r"(-+\s*more\s*-+|--more--|<--- more --->)\s*$", re.IGNORECASE)
# Приглашение CLI: последняя строка вывода. Cisco/Eltex «sw1#», «sw1>»,
# Huawei «<HUAWEI>» / «[HUAWEI]», Juniper «user@mx>», NX-OS «switch#».
_PROMPT = re.compile(r"^(?:<[^<>\s]{1,80}>|\[[^\[\]\s]{1,80}\]|[\w.@:/()~+-]{1,80}[>#%])\s?$")


def clean_output(text: str) -> str:
    """Вырезает управляющие последовательности терминала и забой."""
    text = _ANSI.sub("", text)
    while "\x08" in text:
        text = re.sub(r"[^\x08\n]\x08", "", text, count=1)
        text = text.replace("\n\x08", "\n").lstrip("\x08")
    return text


class NetSession(Protocol):
    """Сессия CLI устройства: выполнить команду просмотра и вернуть текст."""
    banner: str          # баннер SSH-сервера (подсказка о платформе)
    prompt: str          # приглашение CLI ('' в режиме exec)

    def run(self, command: str, timeout: float) -> str: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class NetCliOptions:
    ssh: sshexec.SshOptions
    command_timeout_sec: float = 60.0
    prompt_timeout_sec: float = 15.0


class ExecSession:
    """Команды через exec-канал SSH (MikroTik RouterOS и подобные)."""

    def __init__(self, shell: sshexec.ParamikoShell, banner: str):
        self._shell = shell
        self.banner = banner
        self.prompt = ""

    def run(self, command: str, timeout: float) -> str:
        res = self._shell.run(command, timeout)
        return clean_output(res.stdout.decode("utf-8", "replace"))

    def close(self) -> None:
        self._shell.close()


class ShellSession:
    """Команды через интерактивный канал: конец вывода — по приглашению CLI."""

    _CHUNK = 64 * 1024

    def __init__(self, shell: sshexec.ParamikoShell, banner: str, *,
                 prompt_timeout: float, sleep=time.sleep):
        import paramiko

        self._shell = shell
        self.banner = banner
        self._sleep = sleep
        try:
            self._chan = shell.client.invoke_shell(term="vt100", width=511, height=1000)
            self._chan.settimeout(prompt_timeout)
        except (paramiko.SSHException, OSError, EOFError) as e:
            shell.close()
            raise NetError(f"интерактивный CLI недоступен: {type(e).__name__}: {e}") from e
        self.prompt = self._find_prompt(prompt_timeout)

    def _read_until(self, done, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        buf = ""
        size = 0
        while True:
            if self._chan.recv_ready():
                chunk = self._chan.recv(self._CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_OUTPUT_BYTES:
                    raise NetError("вывод устройства превысил лимит "
                                   f"{MAX_OUTPUT_BYTES // (1024 * 1024)} МБ")
                buf += chunk.decode("utf-8", "replace")
                tail = clean_output(buf[-400:])
                last = tail.rstrip("\n").rsplit("\n", 1)[-1]
                if _MORE.search(last):
                    self._chan.send(" ")
                    continue
                if done(last):
                    return buf
                continue
            if self._chan.exit_status_ready() or self._chan.closed:
                break
            if time.monotonic() > deadline:
                raise sshexec.CommandTimeout(
                    f"устройство не вернуло приглашение CLI за {timeout:.0f} с")
            self._sleep(0.05)
        return buf

    def _find_prompt(self, timeout: float) -> str:
        """Приглашение: последняя строка после входа (и после пустой команды)."""
        text = self._read_until(lambda last: bool(_PROMPT.match(last.strip())), timeout)
        if not _PROMPT.match(clean_output(text).rstrip("\n").rsplit("\n", 1)[-1].strip()):
            self._chan.send("\n")
            text = self._read_until(lambda last: bool(_PROMPT.match(last.strip())), timeout)
        last = clean_output(text).rstrip("\n").rsplit("\n", 1)[-1].strip()
        if not _PROMPT.match(last):
            raise NetError("не удалось определить приглашение CLI устройства")
        return last

    def run(self, command: str, timeout: float) -> str:
        if "\n" in command or "\r" in command:
            raise ValueError("команда CLI в одну строку")
        self._chan.settimeout(timeout)
        self._chan.send(command + "\n")
        prompt = self.prompt
        raw = self._read_until(lambda last: last.strip() == prompt, timeout)
        text = clean_output(raw)
        lines = text.split("\n")
        # эхо команды — первая строка, приглашение — последняя
        if lines and command in lines[0]:
            lines = lines[1:]
        if lines and lines[-1].strip() == prompt:
            lines = lines[:-1]
        return "\n".join(lines)

    def close(self) -> None:
        try:
            self._chan.close()
        finally:
            self._shell.close()


def open_cli(host: str, cred: HostCredential, opts: NetCliOptions, *,
             exec_mode: bool | None = None, connect=sshexec.connect) -> NetSession:
    """Сессия CLI устройства по учётке netssh. host — уже проверенный IP.

    exec_mode=None — по баннеру: RouterOS (``ROSSSH``) — exec, остальные —
    интерактивный CLI. Ошибки входа — исключения `core.sshexec` (AuthFailed,
    HostKeyMismatch, Unreachable/SshTimeout)."""
    shell = connect(host, cred, opts.ssh)
    banner = getattr(shell, "remote_banner", "") or ""
    if exec_mode is None:
        exec_mode = "rosssh" in banner.lower() or cred.options.get("platform") == "routeros"
    if exec_mode:
        return ExecSession(shell, banner)
    return ShellSession(shell, banner, prompt_timeout=opts.prompt_timeout_sec)


# ---------- SNMP ----------

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
# Версии, которых нет в sysDescr: MikroTik (mtxrLicVersion), Huawei (hwSysImageVersion
# не стандартизован — берём sysDescr), Juniper (jnxVirtualChassis… не нужен).
OID_MIKROTIK_VERSION = "1.3.6.1.4.1.14988.1.1.4.4.0"
SYSTEM_OIDS = (OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME, OID_SYS_UPTIME,
               OID_MIKROTIK_VERSION)


@dataclass(slots=True)
class SnmpOptions:
    timeout_sec: float = 3.0
    retries: int = 1


def _auth_data(cred: HostCredential):
    from pysnmp.hlapi.v3arch import asyncio as h

    o = cred.options or {}
    if o.get("snmp_version") == "2c":
        return h.CommunityData(cred.password or "", mpModel=1)
    auth = {"sha": h.usmHMACSHAAuthProtocol, "sha224": h.usmHMAC128SHA224AuthProtocol,
            "sha256": h.usmHMAC192SHA256AuthProtocol,
            "sha384": h.usmHMAC256SHA384AuthProtocol,
            "sha512": h.usmHMAC384SHA512AuthProtocol,
            "md5": h.usmHMACMD5AuthProtocol}[o.get("auth_proto") or "sha"]
    priv_name = o.get("priv_proto") or "aes"
    priv = {"aes": h.usmAesCfb128Protocol,
            "aes192": h.usmAesBlumenthalCfb192Protocol,
            "aes256": h.usmAesBlumenthalCfb256Protocol,
            "aes192c": h.usmAesCfb192Protocol, "aes256c": h.usmAesCfb256Protocol,
            "des": h.usmDESPrivProtocol, "none": h.usmNoPrivProtocol}[priv_name]
    if priv_name == "none":
        return h.UsmUserData(cred.username, cred.password or "", authProtocol=auth,
                             privProtocol=priv)
    return h.UsmUserData(cred.username, cred.password or "", cred.passphrase or "",
                         authProtocol=auth, privProtocol=priv)


_AUTH_ERRORS = ("wrongdigest", "unknownusername", "decryptionerror", "unknownsecuritylevel",
                "authenticationfailure", "unsupportedsecuritylevel", "notintimewindow")


async def _get_async(host: str, cred: HostCredential, oids: tuple[str, ...],
                     opts: SnmpOptions) -> dict[str, str]:
    from pysnmp.hlapi.v3arch import asyncio as h

    engine = h.SnmpEngine()
    try:
        target = await h.UdpTransportTarget.create(
            (host, cred.port), timeout=opts.timeout_sec, retries=opts.retries)
        err, status, _index, binds = await h.get_cmd(
            engine, _auth_data(cred), target, h.ContextData(),
            *(h.ObjectType(h.ObjectIdentity(o)) for o in oids))
    finally:
        engine.close_dispatcher()
    if err:
        name = type(err).__name__.lower() + " " + str(err).lower()
        if "timeout" in name or "timedout" in name:
            raise SnmpTimeout(f"SNMP: агент {host}:{cred.port} не ответил за "
                              f"{opts.timeout_sec:.0f} с (попыток {opts.retries + 1})")
        if any(k in name.replace(" ", "") for k in _AUTH_ERRORS):
            raise SnmpAuthFailed("SNMPv3: логин или ключи отклонены агентом "
                                 f"({type(err).__name__})")
        raise SnmpError(f"SNMP: {type(err).__name__}")
    if status:
        raise SnmpError(f"SNMP: ошибка агента {status.prettyPrint()}")
    out: dict[str, str] = {}
    for oid, value in binds:
        kind = type(value).__name__
        if kind in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
            continue
        text = value.prettyPrint()
        out[str(oid)] = text[:4096]
    return out


def snmp_get(host: str, cred: HostCredential, oids: tuple[str, ...] = SYSTEM_OIDS,
             opts: SnmpOptions | None = None) -> dict[str, str]:
    """GET по OID; {oid: значение} без отсутствующих. Синхронная обёртка
    (модули работают в потоках — у каждого вызова свой цикл событий)."""
    import asyncio

    opts = opts or SnmpOptions()
    try:
        return asyncio.run(_get_async(host, cred, oids, opts))
    except NetError:
        raise
    except (OSError, ValueError) as e:
        raise SnmpError(f"SNMP: {type(e).__name__}: {str(e)[:200]}") from e
