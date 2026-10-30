"""WinRM-подключение к Windows-хосту по учётной записи (HTTPS + NTLM) — pywinrm.

Используется модулем win_inventory. Гарантии те же, что у `sshexec`:

- пароль берётся из памяти процесса (`HostCredential`), в argv, окружение,
  файлы, журнал и тексты ошибок не попадает; на хосте выполняется только
  фиксированный скрипт PowerShell (`-EncodedCommand`), без подстановки ввода;
- таймаут подключения и общий таймаут команды, лимит размера вывода;
- ошибки в типах: нет соединения (`Unreachable`), отказ учётки (`AuthFailed`),
  сертификат не прошёл проверку (`CertMismatch`), прочее (`WinRmError`);
- системный прокси (HTTPS_PROXY) не используется: цель — адрес из allowlist,
  трафик к ней не должен уходить на сторонний узел.

Транспорт — только HTTPS (порт 5986) с NTLM и привязкой к каналу TLS
(channel binding, EPA): перехваченный обмен NTLM нельзя переиспользовать на
другом TLS-соединении. HTTP (5985) — только при явном
`SCANNER_WINRM_ALLOW_HTTP=true`, и тогда сообщения шифруются самим NTLM.

Проверка сертификата хоста (`SCANNER_WINRM_TLS`):

- ``pin`` (по умолчанию) — как TOFU у SSH: отпечаток SHA-256 сертификата
  запоминается при первом входе в `SCANNER_WINRM_KNOWN_CERTS`, дальше
  соединение принимается только с тем же сертификатом (проверяет urllib3 на
  самом соединении, по которому уходит NTLM). Изменился — `CertMismatch`;
  в строгом режиме (`SCANNER_WINRM_STRICT_CERTS=true`) неизвестный — тоже отказ;
- ``ca`` — обычная проверка цепочки и имени по `SCANNER_WINRM_CA_BUNDLE`
  (корпоративный УЦ). Цели — IP, поэтому в сертификате нужен SAN с IP.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic_settings import BaseSettings, SettingsConfigDict

from scanner.core.credentials import AUTH_PASSWORD, PROTOCOL_WINRM, HostCredential
from scanner.core.sshexec import CommandResult

TLS_PIN = "pin"
TLS_CA = "ca"
TLS_MODES = (TLS_PIN, TLS_CA)
HTTP_PORT = 5985


class WinRmError(RuntimeError):
    """Не удалось подключиться или выполнить команду."""


class AuthFailed(WinRmError):
    """Цель отклонила учётные данные."""


class Unreachable(WinRmError):
    """Нет TCP/HTTP-соединения (хост недоступен, порт закрыт, таймаут)."""


class CertMismatch(WinRmError):
    """Сертификат хоста отличается от запомненного или не прошёл проверку."""


class WinShell(Protocol):
    def run_powershell(self, script: str, timeout: float) -> CommandResult: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class WinRmOptions:
    tls: str = TLS_PIN
    known_certs_file: str | None = None
    strict_certs: bool = False           # pin: только сертификаты из known_certs
    ca_bundle: str | None = None         # ca: файл с сертификатами УЦ
    allow_http: bool = False
    connect_timeout_sec: float = 15.0
    operation_timeout_sec: int = 20      # одна операция WS-Man (pywinrm)
    max_output_bytes: int = 32 * 1024 * 1024


class _WinRmSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_WINRM_", env_file=".env",
                                      extra="ignore")

    tls: str = TLS_PIN
    # ./data смонтирован в контейнер как /data — отпечатки переживают пересоздание.
    known_certs: str = "/data/winrm_known_certs"
    strict_certs: bool = False
    ca_bundle: str = ""
    allow_http: bool = False
    connect_timeout_sec: float = 15.0


def options_from_env() -> WinRmOptions:
    s = _WinRmSettings()
    return WinRmOptions(tls=s.tls if s.tls in TLS_MODES else TLS_PIN,
                        known_certs_file=s.known_certs or None,
                        strict_certs=s.strict_certs, ca_bundle=s.ca_bundle or None,
                        allow_http=s.allow_http,
                        connect_timeout_sec=s.connect_timeout_sec)


# ---------- закрепление сертификата (TOFU) ----------

_certs_lock = threading.Lock()


def _endpoint_key(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def load_known_certs(path: str | None) -> dict[str, str]:
    """known_certs: строки «хост:порт sha256-hex». Битые строки пропускаются."""
    out: dict[str, str] = {}
    if not path or not Path(path).is_file():
        return out
    try:
        text = Path(path).read_text(encoding="ascii", errors="ignore")
    except OSError as e:
        raise WinRmError(f"не удалось прочитать {path}: {e}") from e
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[1]) == 64:
            out[parts[0]] = parts[1].lower()
    return out


def _remember_cert(path: str | None, key: str, fingerprint: str) -> None:
    if not path:
        return
    with _certs_lock:
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="ascii") as fh:
                fh.write(f"{key} {fingerprint}\n")
            os.chmod(p, 0o600)
        except OSError:
            pass        # не удалось запомнить: в этом прогоне сертификат принят


def fetch_cert_fingerprint(host: str, port: int, timeout: float) -> str:
    """SHA-256 сертификата, который отдаёт хост (без проверки цепочки)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock) as tls:
            der = tls.getpeercert(binary_form=True)
    except (TimeoutError, ConnectionError, OSError) as e:
        raise Unreachable(f"нет HTTPS-соединения с {host}:{port}: "
                          f"{type(e).__name__}") from e
    if not der:
        raise CertMismatch(f"{host}:{port} не предъявил сертификат")
    return hashlib.sha256(der).hexdigest()


def pinned_fingerprint(host: str, port: int, opts: WinRmOptions,
                       fetch: Callable[[str, int, float], str] = fetch_cert_fingerprint
                       ) -> str:
    """Отпечаток, с которым разрешено соединение: запомненный или новый (TOFU)."""
    key = _endpoint_key(host, port)
    with _certs_lock:
        known = load_known_certs(opts.known_certs_file).get(key)
    if known:
        return known
    if opts.strict_certs:
        raise CertMismatch(f"сертификат {key} неизвестен (строгая проверка "
                           "SCANNER_WINRM_KNOWN_CERTS)")
    fp = fetch(host, port, opts.connect_timeout_sec)
    _remember_cert(opts.known_certs_file, key, fp)
    return fp


# ---------- PowerShell ----------

# Предел командной строки cmd.exe — 8191 символ; скрипты сбора делятся на части,
# чтобы каждая уложилась (проверяется тестом).
MAX_COMMAND_LINE = 8000


def encode_powershell(script: str) -> str:
    """Командная строка для фиксированного скрипта: -EncodedCommand (UTF-16LE)."""
    b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {b64}"


class PyWinRmShell:
    """Сессия pywinrm: один shell, команды по очереди, вывод с лимитом."""

    def __init__(self, protocol, max_output_bytes: int):
        self._p = protocol
        self._max_output = max_output_bytes
        self._shell_id: str | None = None

    def run_powershell(self, script: str, timeout: float) -> CommandResult:
        from winrm.exceptions import WinRMOperationTimeoutError

        deadline = time.monotonic() + timeout
        out, err = bytearray(), bytearray()
        truncated, rc = False, -1
        try:
            if self._shell_id is None:
                self._shell_id = self._p.open_shell(codepage=65001)
            command_id = self._p.run_command(self._shell_id, encode_powershell(script))
            try:
                while True:
                    if time.monotonic() > deadline:
                        raise WinRmError(f"команда не уложилась в {timeout:.0f} с")
                    try:
                        o, e, code, done = self._p.get_command_output_raw(
                            self._shell_id, command_id)
                    except WinRMOperationTimeoutError:
                        continue            # команда ещё работает, вывода нет
                    if len(out) + len(o) > self._max_output:
                        truncated = True
                        break
                    out += o
                    err = (err + e)[-4000:]
                    if done:
                        rc = code
                        break
            finally:
                self._p.cleanup_command(self._shell_id, command_id)
        except WinRmError:
            raise
        except Exception as e:  # noqa: BLE001 — ошибки транспорта переводим в свои
            raise _translate(e) from e
        return CommandResult(rc, bytes(out), err.decode("utf-8", "replace"), truncated)

    def close(self) -> None:
        try:
            if self._shell_id is not None:
                self._p.close_shell(self._shell_id)
        except Exception:  # noqa: BLE001 — закрытие best-effort
            pass
        finally:
            self._shell_id = None
            try:
                self._p.transport.close_session()
            except Exception:  # noqa: BLE001
                pass


def _translate(e: Exception) -> WinRmError:
    """Ошибки requests/pywinrm -> типы модуля. Текст — без учётных данных."""
    import requests
    from winrm.exceptions import InvalidCredentialsError, WinRMTransportError

    if isinstance(e, InvalidCredentialsError):
        return AuthFailed("учётные данные отклонены")
    if isinstance(e, WinRMTransportError):
        if e.code == 401:
            return AuthFailed("учётные данные отклонены")
        return WinRmError(f"WinRM ответил HTTP {e.code}")
    if isinstance(e, requests.exceptions.SSLError):
        text = str(e)
        if "ingerprint" in text:
            return CertMismatch("сертификат хоста изменился: возможна подмена "
                                "(MITM) или перевыпуск — проверьте и удалите старую "
                                "запись из SCANNER_WINRM_KNOWN_CERTS")
        return CertMismatch(f"сертификат хоста не прошёл проверку: {type(e).__name__}")
    if isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                      TimeoutError, ConnectionError)):
        return Unreachable(f"нет WinRM-соединения: {type(e).__name__}")
    return WinRmError(f"{type(e).__name__}: {str(e)[:300]}")


def _fingerprint_adapter(fingerprint: str):
    """HTTPAdapter, который принимает только сертификат с этим отпечатком."""
    from requests.adapters import HTTPAdapter

    class _Pinned(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["assert_fingerprint"] = fingerprint
            kwargs["cert_reqs"] = ssl.CERT_NONE        # цепочку заменяет отпечаток
            kwargs["assert_hostname"] = False
            super().init_poolmanager(*args, **kwargs)

    return _Pinned()


def connect(host: str, cred: HostCredential, opts: WinRmOptions) -> WinShell:
    """WinRM-сессия с хостом по учётке. host — уже проверенный allowlist-ом IP."""
    from winrm.protocol import Protocol as WinRmProtocol

    if cred.protocol != PROTOCOL_WINRM or cred.auth != AUTH_PASSWORD:
        raise WinRmError("учётка не предназначена для WinRM (нужен протокол winrm "
                         "и вход по паролю)")
    https = cred.port != HTTP_PORT
    if not https and not opts.allow_http:
        raise WinRmError("WinRM по HTTP (5985) выключен: используйте HTTPS 5986 или "
                         "SCANNER_WINRM_ALLOW_HTTP=true")
    addr = f"[{host}]" if ":" in host else host
    endpoint = f"{'https' if https else 'http'}://{addr}:{cred.port}/wsman"
    fingerprint = None
    if https and opts.tls == TLS_PIN:
        fingerprint = pinned_fingerprint(host, cred.port, opts)
    op = max(1, int(opts.operation_timeout_sec))
    protocol = WinRmProtocol(
        endpoint, transport="ntlm", username=cred.username, password=cred.password,
        server_cert_validation="validate" if https and opts.tls == TLS_CA else "ignore",
        ca_trust_path=opts.ca_bundle if opts.tls == TLS_CA else None,
        read_timeout_sec=max(op + 10, int(opts.connect_timeout_sec) + op),
        operation_timeout_sec=op,
        message_encryption="auto" if https else "always",
        send_cbt=True, proxy=None)
    session = protocol.transport.build_session()
    if fingerprint:
        session.mount("https://", _fingerprint_adapter(fingerprint))
    shell = PyWinRmShell(protocol, opts.max_output_bytes)
    try:
        # первое обращение — открытие shell: здесь проходят TLS и NTLM
        shell._shell_id = protocol.open_shell(codepage=65001)
    except Exception as e:  # noqa: BLE001
        shell.close()
        raise _translate(e) from e
    return shell
