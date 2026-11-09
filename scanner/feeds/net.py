"""Скачивание справочников с сайтов вендоров: общие заголовки, доверенные
корневые сертификаты и понятные оператору причины сбоя.

Почему не «голый» httpx:
* часть российских сайтов (bdu.fstec.ru, сайты вендоров ОС) выдаёт сертификаты
  от Russian Trusted Root CA (УЦ Минцифры) — его нет в certifi, и загрузка
  падает с ``CERTIFICATE_VERIFY_FAILED``. Поэтому доверяем: certifi + системному
  хранилищу контейнера + сертификатам из каталога ``SCANNER_CA_DIR``
  (по умолчанию ``/data/certs`` = ``./data/certs`` на хосте);
* защита от ботов на сайтах вендоров отвечает 403 на клиент без
  User-Agent/Accept — отправляем обычные заголовки (свой — ``SCANNER_HTTP_USER_AGENT``);
* вместо файла сервер может отдать HTML (страница блокировки, капча, «404» с
  кодом 200) — это распознаётся и называется прямо, а не «ошибка разбора XML».
Прокси берётся из окружения (HTTPS_PROXY / NO_PROXY), как у любого httpx.
"""
from __future__ import annotations

import os
import ssl
from functools import lru_cache
from pathlib import Path

DEFAULT_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) scanner-way-feeds/1.0")
CA_SUFFIXES = (".crt", ".pem", ".cer")


class DownloadError(Exception):
    """Понятная оператору причина, почему файл не скачался."""


def ca_dir() -> Path:
    return Path(os.environ.get("SCANNER_CA_DIR") or "/data/certs")


def user_agent() -> str:
    return os.environ.get("SCANNER_HTTP_USER_AGENT", "").strip() or DEFAULT_USER_AGENT


def extra_ca_files(directory: Path | None = None) -> list[Path]:
    d = directory or ca_dir()
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix.lower() in CA_SUFFIXES)


def build_ssl_context(directory: Path | None = None) -> ssl.SSLContext:
    """certifi + системные корневые + сертификаты оператора (PEM или DER)."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:                 # pragma: no cover — certifi ставится с httpx
        ctx = ssl.create_default_context()
    try:
        ctx.load_default_certs()
    except ssl.SSLError:                # pragma: no cover
        pass
    for path in extra_ca_files(directory):
        data = path.read_bytes()
        try:
            if b"-----BEGIN" in data:
                ctx.load_verify_locations(cadata=data.decode("ascii", "ignore"))
            else:
                ctx.load_verify_locations(cadata=data)      # DER
        except (ssl.SSLError, ValueError) as e:
            raise DownloadError(f"сертификат {path} не читается: {e}") from e
    return ctx


@lru_cache(maxsize=4)
def _cached_context(directory: str, stamp: tuple[tuple[str, float], ...]) -> ssl.SSLContext:
    return build_ssl_context(Path(directory))


def ssl_context() -> ssl.SSLContext:
    """Контекст пересобирается, если оператор добавил/сменил файл в каталоге."""
    d = ca_dir()
    stamp = tuple((p.name, p.stat().st_mtime) for p in extra_ca_files(d))
    return _cached_context(str(d), stamp)


def headers() -> dict[str, str]:
    return {"User-Agent": user_agent(),
            "Accept": "application/xml,application/json,application/octet-stream,*/*;q=0.8",
            "Accept-Language": "ru,en;q=0.8"}


_HTML_MARKERS = (b"<!doctype html", b"<html", b"<head", b"<body")


def looks_like_html(head: bytes) -> bool:
    """Начало файла — HTML-страница, а не данные (XML/JSON/архив)."""
    h = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()[:512]
    return any(h.startswith(m) for m in _HTML_MARKERS) or (
        h.startswith(b"<") and b"<html" in h)


def explain(url: str, exc: Exception) -> str:
    """Причина сбоя скачивания словами оператора."""
    import httpx
    text = f"{type(exc).__name__}: {exc}"
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        hint = {403: "доступ запрещён — сайт блокирует запрос (защита от ботов, "
                     "доступ только из РФ или через прокси)",
                404: "файла по этому адресу нет — вендор мог перенести выгрузку",
                407: "прокси требует авторизацию",
                429: "сайт ограничил частоту запросов — повторите позже"}.get(
            code, "сервер вернул ошибку" if code >= 500 else "запрос отклонён")
        return f"{url}: HTTP {code} — {hint}"
    low = text.lower()
    if "certificate" in low or "ssl" in low:
        return (f"{url}: сертификат сайта не прошёл проверку ({text[:160]}). Если сайт "
                "использует российский УЦ (Russian Trusted Root CA Минцифры), положите "
                f"корневой сертификат (.crt/.pem) в {ca_dir()} (на хосте ./data/certs)")
    if isinstance(exc, httpx.ProxyError):
        return f"{url}: прокси отказал в соединении ({text[:160]}) — проверьте HTTPS_PROXY"
    if isinstance(exc, httpx.TimeoutException):
        return f"{url}: нет ответа (таймаут) — проверьте доступ в интернет/прокси"
    if isinstance(exc, httpx.ConnectError):
        return (f"{url}: не удалось подключиться ({text[:160]}) — проверьте DNS, доступ "
                "в интернет и HTTPS_PROXY")
    return f"{url}: {text[:300]}"


def download(url: str, dest: Path, *, timeout: float = 300,
             allow_html: bool = False) -> None:
    """Скачивает ``url`` в ``dest``; HTML вместо данных — ошибка (кроме
    оглавлений каталогов: ``allow_html``)."""
    import httpx
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True,
                          headers=headers(), verify=ssl_context()) as resp:
            resp.raise_for_status()
            head = b""
            with dest.open("wb") as fh:
                for chunk in resp.iter_bytes(1 << 20):
                    if not allow_html and len(head) < 512:
                        head += chunk[:512]
                        if looks_like_html(head):
                            raise DownloadError(
                                f"{url}: сервер вернул HTML-страницу вместо файла данных "
                                "(страница блокировки/капча или адрес сменился)")
                    fh.write(chunk)
    except httpx.HTTPError as e:
        raise DownloadError(explain(url, e)) from e
    except ssl.SSLError as e:                      # pragma: no cover — обычно внутри httpx
        raise DownloadError(explain(url, e)) from e


def kind_of(head: bytes) -> str:
    """Что лежит в начале файла: xml | json | bz2 | gzip | zip | html | ?"""
    h = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if h.startswith(b"BZh"):
        return "bz2"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"PK"):
        return "zip"
    if looks_like_html(h):
        return "html"
    if h.startswith(b"<"):
        return "xml"
    if h[:1] in (b"{", b"["):
        return "json"
    return "?"


def probe(url: str, *, timeout: float = 30, limit: int = 4096) -> tuple[int, str, bytes]:
    """Проверка адреса без скачивания целиком -> (HTTP-код, Content-Type, начало)."""
    import httpx
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True,
                          headers=headers(), verify=ssl_context()) as resp:
            head = b""
            if resp.status_code < 400:
                for chunk in resp.iter_bytes(limit):
                    head += chunk
                    if len(head) >= limit:
                        break
            return resp.status_code, resp.headers.get("content-type", ""), head[:limit]
    except httpx.HTTPError as e:
        raise DownloadError(explain(url, e)) from e
