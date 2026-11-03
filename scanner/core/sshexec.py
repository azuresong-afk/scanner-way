"""SSH-подключение к цели по учётной записи (пароль или ключ) — paramiko.

Используется инвентаризацией (auth_inventory) и аудитом конфигураций
(config_audit). Почему не системный `ssh`: пароль пришлось бы передавать через
argv/окружение/sshpass, а ключ — писать во временный файл. paramiko берёт
пароль и ключ из памяти процесса, на диск и в argv они не попадают. Пароль для
`sudo -S` уходит в stdin канала (`ParamikoShell.run(..., stdin=...)`), файлы
на цель — по SFTP (`put`).

Проверка ключа хоста — как `StrictHostKeyChecking=accept-new` (TOFU):
неизвестный ключ запоминается в known_hosts, ИЗМЕНИВШИЙСЯ ключ — отказ
(`HostKeyMismatch`), в строгом режиме неизвестный ключ — тоже отказ.
В known_hosts только дописываются строки: файл общий с системным ssh.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic_settings import BaseSettings, SettingsConfigDict

from scanner.core.credentials import AUTH_KEY, HostCredential, load_private_key


class SshError(RuntimeError):
    """Не удалось подключиться или выполнить команду."""


class AuthFailed(SshError):
    """Цель отклонила учётные данные."""


class Unreachable(SshError):
    """Нет TCP/SSH-соединения (хост недоступен, порт закрыт, таймаут)."""


class SshTimeout(Unreachable):
    """Таймаут: TCP-порт не ответил (фильтруется), нет SSH-баннера или
    вход не уложился в отведённое время."""


class CommandTimeout(SshError):
    """Команда на цели не уложилась в отведённое время."""


class HostKeyMismatch(SshError):
    """Ключ хоста отличается от запомненного или неизвестен в строгом режиме."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: str
    truncated: bool = False


class RemoteShell(Protocol):
    def run(self, command: str, timeout: float,
            stdin: bytes | None = None) -> CommandResult: ...
    def put(self, path: str, data: bytes, timeout: float) -> None: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class SshOptions:
    known_hosts_file: str | None = None
    strict_host_keys: bool = False        # True — только ключи из known_hosts
    connect_timeout_sec: float = 15.0
    max_output_bytes: int = 32 * 1024 * 1024
    # Предварительная проверка TCP/SSH перед входом и ограниченный повтор
    # при таймауте (всего попыток; пауза между ними — retry_delay_sec).
    preflight: bool = True
    attempts: int = 2
    retry_delay_sec: float = 3.0


class _SshSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_SSH_", env_file=".env",
                                      extra="ignore")

    # ./data смонтирован в контейнер как /data — ключи хостов переживают
    # пересоздание контейнера.
    known_hosts: str = "/data/ssh_known_hosts"
    strict_host_keys: bool = False
    connect_timeout_sec: float = 15.0
    preflight: bool = True
    attempts: int = 2
    retry_delay_sec: float = 3.0


def options_from_env() -> SshOptions:
    s = _SshSettings()
    return SshOptions(known_hosts_file=s.known_hosts or None,
                      strict_host_keys=s.strict_host_keys,
                      connect_timeout_sec=s.connect_timeout_sec,
                      preflight=s.preflight, attempts=max(1, min(s.attempts, 5)),
                      retry_delay_sec=max(0.0, s.retry_delay_sec))


# ---------- предварительная проверка TCP/SSH ----------
REC_FILTERED = ("Порт не ответил (пакеты отбрасываются). Проверьте межсетевой экран "
                "между сканером и хостом (разрешите TCP/{port} с адреса сканера) и "
                "что хост включён.")
REC_CLOSED = ("Порт закрыт (соединение отклонено). Проверьте, что служба sshd "
              "запущена и слушает порт {port}, и порт в учётной записи указан верно.")
REC_NO_BANNER = ("TCP-соединение установлено, но SSH-баннер не получен за {t:.0f} с. "
                 "Возможны: перегрузка sshd (MaxStartups), IPS/прокси на пути, не SSH "
                 "на этом порту. Проверьте sshd на хосте или увеличьте "
                 "SCANNER_SSH_CONNECT_TIMEOUT_SEC.")
REC_LOGIN_TIMEOUT = ("Вход по SSH не уложился в {t:.0f} с (медленный DNS/GSSAPI на "
                     "хосте, перегрузка). Отключите UseDNS/GSSAPIAuthentication в sshd "
                     "или увеличьте SCANNER_SSH_CONNECT_TIMEOUT_SEC.")


def preflight_ssh(host: str, port: int, timeout: float) -> None:
    """TCP connect + чтение SSH-баннера. Ничего не отправляет, кроме TCP
    рукопожатия. Бросает SshTimeout/Unreachable с рекомендацией оператору."""
    import errno
    import ipaddress
    import socket

    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((host, port))
        except TimeoutError as e:
            raise SshTimeout(f"{host}:{port}: таймаут TCP за {timeout:.0f} с. "
                             + REC_FILTERED.format(port=port)) from e
        except OSError as e:
            raise Unreachable(f"{host}:{port}: {e}. "
                              + REC_FILTERED.format(port=port)) from e
        if code == errno.ECONNREFUSED:
            raise Unreachable(f"{host}:{port}: соединение отклонено. "
                              + REC_CLOSED.format(port=port))
        if code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS):
            raise SshTimeout(f"{host}:{port}: таймаут TCP за {timeout:.0f} с. "
                             + REC_FILTERED.format(port=port))
        if code != 0:
            raise Unreachable(f"{host}:{port}: {os.strerror(code)}. "
                              + REC_FILTERED.format(port=port))
        try:
            banner = sock.recv(256)
        except TimeoutError as e:
            raise SshTimeout(f"{host}:{port}: " + REC_NO_BANNER.format(t=timeout)) from e
        except OSError as e:
            raise Unreachable(f"{host}:{port}: соединение разорвано до SSH-баннера "
                              f"({e})") from e
        if not banner.startswith(b"SSH-"):
            raise SshError(f"{host}:{port}: на порту не SSH (ответ "
                           f"{banner[:40]!r}) — проверьте порт в учётной записи")


_known_hosts_lock = threading.Lock()


class _TofuPolicy:
    """Политика для неизвестного ключа хоста: запомнить (TOFU) или отказать."""

    def __init__(self, opts: SshOptions):
        self.opts = opts

    def missing_host_key(self, client, hostname: str, key) -> None:
        if self.opts.strict_host_keys:
            raise HostKeyMismatch(f"ключ хоста {hostname} неизвестен "
                                  "(строгая проверка known_hosts)")
        client.get_host_keys().add(hostname, key.get_name(), key)
        path = self.opts.known_hosts_file
        if not path:
            return
        line = f"{hostname} {key.get_name()} {key.get_base64()}\n"
        with _known_hosts_lock:
            try:
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "a", encoding="ascii") as fh:
                    fh.write(line)
                os.chmod(p, 0o600)
            except OSError:
                pass        # не удалось запомнить: в этом прогоне ключ принят


class ParamikoShell:
    _CHUNK = 64 * 1024

    def __init__(self, client, max_output_bytes: int):
        self._client = client
        self._max_output = max_output_bytes

    def run(self, command: str, timeout: float,
            stdin: bytes | None = None) -> CommandResult:
        """Выполнить команду; stdout — не больше max_output_bytes (остальное
        отбрасывается, truncated=True), stderr — последние 4 КБ.

        stdin — данные для stdin команды (пароль для `sudo -S`): уходят в канал
        SSH и нигде больше не сохраняются; после них stdin закрывается.
        """
        import paramiko

        try:
            chan = self._client.get_transport().open_session(timeout=timeout)
            chan.settimeout(timeout)
            chan.exec_command(command)
            if stdin:
                chan.sendall(stdin)
            chan.shutdown_write()
            deadline = time.monotonic() + timeout
            out, err = bytearray(), bytearray()
            truncated = False
            while True:
                if time.monotonic() > deadline:
                    raise CommandTimeout(f"команда не уложилась в {timeout:.0f} с")
                if chan.recv_ready():
                    chunk = chan.recv(self._CHUNK)
                    if len(out) + len(chunk) > self._max_output:
                        truncated = True
                        break
                    out += chunk
                elif chan.recv_stderr_ready():
                    err = (err + chan.recv_stderr(self._CHUNK))[-4000:]
                elif chan.exit_status_ready():
                    break
                else:
                    time.sleep(0.02)
            rc = -1 if truncated else chan.recv_exit_status()
            chan.close()
        except TimeoutError as e:
            raise CommandTimeout(f"команда не уложилась в {timeout:.0f} с") from e
        except (paramiko.SSHException, OSError, EOFError) as e:
            raise SshError(f"{type(e).__name__}: {e}") from e
        return CommandResult(rc, bytes(out), err.decode("utf-8", "replace"), truncated)

    def put(self, path: str, data: bytes, timeout: float) -> None:
        """Записать файл на цель по SFTP (права 0600). path — путь, построенный
        сканером (не из ввода цели)."""
        import paramiko

        try:
            sftp = self._client.open_sftp()
        except (paramiko.SSHException, OSError, EOFError) as e:
            raise SshError(f"SFTP недоступен: {type(e).__name__}: {e}") from e
        try:
            sftp.get_channel().settimeout(timeout)
            with sftp.open(path, "wb") as fh:
                fh.set_pipelined(True)
                fh.write(data)
            sftp.chmod(path, 0o600)
        except TimeoutError as e:
            raise SshError(f"передача по SFTP не уложилась в {timeout:.0f} с") from e
        except (paramiko.SSHException, OSError, EOFError) as e:
            raise SshError(f"SFTP: {type(e).__name__}: {e}") from e
        finally:
            sftp.close()

    def close(self) -> None:
        self._client.close()


def connect(host: str, cred: HostCredential, opts: SshOptions, *,
            sleep=time.sleep) -> RemoteShell:
    """SSH-сессия с хостом по учётке. host — уже проверенный allowlist-ом IP.

    Сначала — предварительная проверка TCP/SSH (быстрый понятный отказ вместо
    общего TimeoutError), при таймауте — ограниченный повтор (opts.attempts).
    Отказ в учётке и несовпадение ключа хоста не повторяются."""
    attempts = max(1, opts.attempts)
    for attempt in range(1, attempts + 1):
        try:
            if opts.preflight:
                preflight_ssh(host, cred.port, opts.connect_timeout_sec)
            return _connect_once(host, cred, opts)
        except SshTimeout as e:
            if attempt >= attempts:
                if attempts > 1:
                    raise SshTimeout(f"{e} (попыток: {attempts})") from e
                raise
            sleep(opts.retry_delay_sec)
    raise AssertionError("unreachable")


def _connect_once(host: str, cred: HostCredential, opts: SshOptions) -> RemoteShell:
    import paramiko

    client = paramiko.SSHClient()
    if opts.known_hosts_file and Path(opts.known_hosts_file).is_file():
        try:
            client.load_host_keys(opts.known_hosts_file)
        except (OSError, paramiko.SSHException) as e:
            raise SshError(f"не удалось прочитать known_hosts: {e}") from e
    client.set_missing_host_key_policy(_TofuPolicy(opts))
    timeout = opts.connect_timeout_sec
    kwargs = {"hostname": host, "port": cred.port, "username": cred.username,
              "timeout": timeout, "banner_timeout": timeout, "auth_timeout": timeout,
              "look_for_keys": False, "allow_agent": False}
    if cred.auth == AUTH_KEY:
        kwargs["pkey"] = load_private_key(cred.private_key or "", cred.passphrase)
    else:
        kwargs["password"] = cred.password
    try:
        client.connect(**kwargs)
    except paramiko.BadHostKeyException as e:
        client.close()
        raise HostKeyMismatch(f"ключ хоста {host} изменился: возможна подмена "
                              "(MITM) или переустановка — проверьте и удалите "
                              "старую запись из known_hosts") from e
    except HostKeyMismatch:
        client.close()
        raise
    except paramiko.AuthenticationException as e:
        client.close()
        raise AuthFailed("учётные данные отклонены") from e
    except TimeoutError as e:
        client.close()
        raise SshTimeout(f"{host}:{cred.port}: таймаут SSH ({type(e).__name__}). "
                         + REC_LOGIN_TIMEOUT.format(t=timeout)) from e
    except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionError) as e:
        client.close()
        raise Unreachable(f"нет SSH-соединения: {type(e).__name__}. "
                          + REC_CLOSED.format(port=cred.port)) from e
    except (paramiko.SSHException, OSError, EOFError) as e:
        client.close()
        if "banner" in str(e).lower() or "timed out" in str(e).lower():
            raise SshTimeout(f"{host}:{cred.port}: {e}. "
                             + REC_NO_BANNER.format(t=timeout)) from e
        raise SshError(f"{type(e).__name__}: {e}") from e
    return ParamikoShell(client, opts.max_output_bytes)


def failure_status(e: BaseException) -> str:
    """Статус покрытия (scanner.core.coverage) по ошибке SSH."""
    from scanner.core import coverage as cov
    if isinstance(e, (SshTimeout, CommandTimeout)):
        return cov.TIMEOUT
    if isinstance(e, Unreachable):
        return cov.UNREACHABLE
    return cov.ERROR
