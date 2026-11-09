"""Скачивание справочников: заголовки, HTML вместо данных, свои корневые сертификаты."""
from __future__ import annotations

import http.server
import ssl
import subprocess
import threading

import httpx
import pytest

from scanner.feeds import net


@pytest.fixture()
def server():
    pages: dict[str, tuple[int, str, bytes]] = {}
    seen: list[dict[str, str]] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(self.headers))
            code, ctype, body = pages.get(self.path, (404, "text/plain", b"nope"))
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, pages, seen
    srv.shutdown()


def test_download_sends_headers_and_saves(server, tmp_path, monkeypatch):
    base, pages, seen = server
    monkeypatch.setenv("SCANNER_CA_DIR", str(tmp_path / "none"))
    pages["/redos.xml"] = (200, "application/xml", b"<?xml version='1.0'?><oval_definitions/>")
    dest = tmp_path / "f"
    net.download(f"{base}/redos.xml", dest)
    assert dest.read_bytes().startswith(b"<?xml")
    assert "scanner-way" in seen[0]["User-Agent"] and seen[0]["Accept"]


def test_download_rejects_html_page(server, tmp_path, monkeypatch):
    base, pages, _ = server
    monkeypatch.setenv("SCANNER_CA_DIR", str(tmp_path / "none"))
    pages["/redos.xml"] = (200, "text/html", b"\n<!DOCTYPE html><html><body>captcha</body>")
    with pytest.raises(net.DownloadError, match="HTML-страницу"):
        net.download(f"{base}/redos.xml", tmp_path / "f")
    # оглавление каталога — HTML можно
    net.download(f"{base}/redos.xml", tmp_path / "g", allow_html=True)


def test_download_explains_http_errors(server, tmp_path, monkeypatch):
    base, pages, _ = server
    monkeypatch.setenv("SCANNER_CA_DIR", str(tmp_path / "none"))
    pages["/x"] = (403, "text/html", b"forbidden")
    with pytest.raises(net.DownloadError, match="HTTP 403 — доступ запрещён"):
        net.download(f"{base}/x", tmp_path / "f")
    with pytest.raises(net.DownloadError, match="HTTP 404 — файла по этому адресу нет"):
        net.download(f"{base}/missing", tmp_path / "f")
    code, _ctype, head = net.probe(f"{base}/x")
    assert code == 403 and head == b""


def test_explain_certificate_error_points_to_ca_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("SCANNER_CA_DIR", str(tmp_path / "certs"))
    msg = net.explain("https://bdu.fstec.ru/x", httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))
    assert "Russian Trusted Root CA" in msg and str(tmp_path / "certs") in msg


def test_kind_of_and_html_detection():
    assert net.kind_of(b"BZh91AY") == "bz2"
    assert net.kind_of(b"\x1f\x8b\x08") == "gzip"
    assert net.kind_of(b"PK\x03\x04") == "zip"
    assert net.kind_of(b"<?xml version='1.0'?><oval_definitions>") == "xml"
    assert net.kind_of(b'{"packages": []}') == "json"
    assert net.kind_of(b"<!doctype html><html>") == "html"
    assert net.kind_of(b"<?xml version='1.0'?>\n<html><body>") == "html"


def _make_ca(tmp_path, name="ca"):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=Test Root CA", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)
    return crt


def test_extra_ca_files_loaded_pem_and_der(tmp_path):
    pytest.importorskip("certifi")
    certs = tmp_path / "certs"
    certs.mkdir()
    crt = _make_ca(tmp_path)
    (certs / "russian_trusted_root_ca.crt").write_bytes(crt.read_bytes())
    der = ssl.PEM_cert_to_DER_cert(crt.read_text())
    (certs / "other.cer").write_bytes(der)
    (certs / "readme.txt").write_text("not a cert")
    base = net.build_ssl_context(tmp_path / "empty").cert_store_stats()["x509_ca"]
    ctx = net.build_ssl_context(certs)
    assert ctx.cert_store_stats()["x509_ca"] >= base + 1
    names = [c["subject"] for c in ctx.get_ca_certs()]
    assert any(("commonName", "Test Root CA") in sum(s, ()) for s in names)


def test_bad_ca_file_is_reported(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    with pytest.raises(net.DownloadError, match="broken.pem"):
        net.build_ssl_context(certs)
