"""SSH-подключение к цели по учётной записи (пароль или ключ) — paramiko.

Почему не системный `ssh`, как в аудите конфигураций: пароль пришлось бы
передавать через argv/окружение/sshpass, а ключ — писать во временный файл.
paramiko берёт пароль и ключ из памяти процесса, на диск и в argv они не
попадают.

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


class HostKeyMismatch(SshError):
    """Ключ хоста отличается от запомненного или неизвестен в строгом режиме."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: str
    truncated: bool = False


class RemoteShell(Protocol):
    def run(self, command: str, timeout: float) -> CommandResult: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class SshOptions:
    known_hosts_file: str | None = None
    strict_host_keys: bool = False        # True — только ключи из known_hosts
    connect_timeout_sec: float = 15.0
    max_output_bytes: int = 32 * 1024 * 1024


class _SshSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_SSH_", env_file=".env",
                                      extra="ignore")

    # ./data смонтирован в контейнер как /data — ключи хостов переживают
    # пересоздание контейнера.
    known_hosts: str = "/data/ssh_known_hosts"
    strict_host_keys: bool = False
    connect_timeout_sec: float = 15.0


def options_from_env() -> SshOptions:
    s = _SshSettings()
    return SshOptions(known_hosts_file=s.known_hosts or None,
                      strict_host_keys=s.strict_host_keys,
                      connect_timeout_sec=s.connect_timeout_sec)


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

    def run(self, command: str, timeout: float) -> CommandResult:
        """Выполнить команду; stdout — не больше max_output_bytes (остальное
        отбрасывается, truncated=True), stderr — последние 4 КБ."""
        import paramiko

        try:
            chan = self._client.get_transport().open_session(timeout=timeout)
            chan.settimeout(timeout)
            chan.exec_command(command)
            chan.shutdown_write()
            deadline = time.monotonic() + timeout
            out, err = bytearray(), bytearray()
            truncated = False
            while True:
                if time.monotonic() > deadline:
                    raise SshError(f"команда не уложилась в {timeout:.0f} с")
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
            raise SshError(f"команда не уложилась в {timeout:.0f} с") from e
        except (paramiko.SSHException, OSError, EOFError) as e:
            raise SshError(f"{type(e).__name__}: {e}") from e
        return CommandResult(rc, bytes(out), err.decode("utf-8", "replace"), truncated)

    def close(self) -> None:
        self._client.close()


def connect(host: str, cred: HostCredential, opts: SshOptions) -> RemoteShell:
    """SSH-сессия с хостом по учётке. host — уже проверенный allowlist-ом IP."""
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
    except (paramiko.ssh_exception.NoValidConnectionsError, TimeoutError, ConnectionError) as e:
        client.close()
        raise Unreachable(f"нет SSH-соединения: {type(e).__name__}") from e
    except (paramiko.SSHException, OSError, EOFError) as e:
        client.close()
        raise SshError(f"{type(e).__name__}: {e}") from e
    return ParamikoShell(client, opts.max_output_bytes)
