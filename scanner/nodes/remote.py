"""Связь узла с центром: HTTPS-клиент и справочники через центр.

Узел всегда сам инициирует соединение (исходящий HTTPS на центр), входящих
портов на узле нет. Аутентификация — токен узла (Authorization: Bearer);
поверх неё по желанию mTLS: сертификат узла (SCANNER_NODE_CLIENT_CERT/KEY)
проверяет обратный прокси центра (nginx ssl_verify_client), а узел проверяет
сертификат центра по своему CA (SCANNER_NODE_CA).
"""
from __future__ import annotations

import gzip
import json
import logging
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx

from scanner.nodes.codec import from_wire

log = logging.getLogger(__name__)
API_PREFIX = "/api/node/v1"


class NodeApiError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NodeClient:
    def __init__(self, server: str, token: str, *, ca: str | None = None,
                 client_cert: str | None = None, client_key: str | None = None,
                 timeout: float = 60.0, transport: httpx.BaseTransport | None = None,
                 prefix: str = API_PREFIX, allow_http: bool = False):
        if not server:
            raise ValueError("не задан адрес центра (SCANNER_NODE_SERVER)")
        if not token:
            raise ValueError("не задан токен узла (SCANNER_NODE_TOKEN)")
        if transport is None and not server.lower().startswith("https://") \
                and not (allow_http or _is_local(server)):
            raise ValueError("связь с центром — только по HTTPS (SCANNER_NODE_SERVER=https://…); "
                             "для стенда без TLS — SCANNER_NODE_ALLOW_HTTP=1")
        cert = None
        if client_cert:
            cert = (client_cert, client_key) if client_key else client_cert
        self.prefix = prefix
        self._http = httpx.Client(
            base_url=server.rstrip("/"), timeout=timeout, transport=transport,
            verify=ca if ca else True, cert=cert,
            headers={"Authorization": f"Bearer {token}",
                     "User-Agent": "scanner-node"})
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def _post(self, path: str, body: Any = None, *, compress: bool = False) -> Any:
        url = self.prefix + path
        data = json.dumps(body if body is not None else {}, ensure_ascii=False).encode()
        headers = {"Content-Type": "application/json"}
        if compress:
            data = gzip.compress(data, 6)
            headers["Content-Encoding"] = "gzip"
        try:
            with self._lock:
                r = self._http.post(url, content=data, headers=headers)
        except httpx.HTTPError as e:
            raise NodeApiError(f"центр недоступен: {type(e).__name__}: {e}") from e
        if r.status_code == 204:
            return None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = r.text[:300]
            raise NodeApiError(f"центр ответил {r.status_code}: {detail}", r.status_code)
        try:
            return r.json()
        except ValueError as e:
            raise NodeApiError("центр вернул не JSON") from e

    # --- протокол узла ---
    def hello(self, info: dict) -> dict:
        return self._post("/hello", info)

    def next_job(self) -> dict | None:
        res = self._post("/jobs/next")
        return (res or {}).get("job")

    def heartbeat(self, run_id: int, progress: dict | None = None) -> dict:
        return self._post(f"/jobs/{run_id}/heartbeat", {"progress": progress})

    def events(self, run_id: int, events: list[dict]) -> None:
        self._post(f"/jobs/{run_id}/events", {"events": events})

    def audit(self, run_id: int, records: list[dict]) -> None:
        self._post(f"/jobs/{run_id}/audit", {"records": records}, compress=True)

    def result(self, run_id: int, payload: dict) -> dict:
        return self._post(f"/jobs/{run_id}/result", payload, compress=True)

    def fail(self, run_id: int, error: str) -> None:
        self._post(f"/jobs/{run_id}/fail", {"error": error[:1000]})

    def download_templates(self, dest: Path, etag: str | None = None) -> str | None:
        """Архив шаблонов Nuclei центра в dest. -> новый ETag; None — не изменился."""
        headers = {"If-None-Match": f'"{etag}"'} if etag else {}
        try:
            with self._lock, self._http.stream("GET", self.prefix + "/nuclei-templates",
                                               headers=headers, timeout=600) as r:
                if r.status_code == 304:
                    return None
                if r.status_code >= 400:
                    raise NodeApiError(f"центр ответил {r.status_code} на запрос шаблонов",
                                       r.status_code)
                with open(dest, "wb") as fh:
                    fh.writelines(r.iter_bytes())
                return (r.headers.get("etag") or "").strip('"') or "unknown"
        except httpx.HTTPError as e:
            raise NodeApiError(f"центр недоступен: {type(e).__name__}: {e}") from e

    def reference(self, store: str, method: str, args: list[Any]) -> Any:
        res = self._post("/reference", {"store": store, "method": method, "args": args})
        return from_wire((res or {}).get("result"))


def _is_local(server: str) -> bool:
    host = httpx.URL(server).host
    return host in ("localhost", "127.0.0.1", "::1")


# ---------- справочники через центр (только чтение) ----------
class _Remote:
    def __init__(self, client: NodeClient, store: str):
        self._client = client
        self._store = store

    def _call(self, method: str, *args: Any) -> Any:
        return self._client.reference(self._store, method, list(args))

    @staticmethod
    def _readonly(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("справочники узла только для чтения: обновляются в центре")


class RemoteReferenceStore(_Remote):
    """ReferenceStore (scanner.feeds.store) через центр."""

    def __init__(self, client: NodeClient):
        super().__init__(client, "reference")

    upsert_bdu = upsert_nvd = _Remote._readonly

    def get_nvd(self, cve_id: str):
        return self._call("get_nvd", cve_id)

    def get_bdu(self, bdu_id: str):
        return self._call("get_bdu", bdu_id)

    def bdu_by_cve(self, cve_id: str):
        return list(self._call("bdu_by_cve", cve_id) or [])

    def cpe_matches(self, product: str):
        return list(self._call("cpe_matches", product) or [])

    def bdu_by_software(self, name: str):
        return list(self._call("bdu_by_software", name) or [])

    def bdu_software_names(self) -> set[str]:
        return set(self._call("bdu_software_names") or ())


class RemoteAdvisoryStore(_Remote):
    """AdvisoryStore (бюллетени дистрибутивов) через центр."""

    def __init__(self, client: NodeClient):
        super().__init__(client, "advisory")

    replace_release = _Remote._readonly

    def releases(self) -> set[tuple[str, str]]:
        return {tuple(x) for x in (self._call("releases") or ())}

    def for_packages(self, family: str, release: str, names: Iterable[str]):
        return dict(self._call("for_packages", family, release, sorted(set(names))) or {})

    def with_prefix(self, family: str, release: str, prefix: str):
        return dict(self._call("with_prefix", family, release, prefix) or {})


class RemoteMsrcStore(_Remote):
    """Справочник MSRC через центр (с кэшем на время прогона)."""

    def __init__(self, client: NodeClient):
        super().__init__(client, "msrc")
        self._fixes: dict[str, list] = {}
        self._count: int | None = None
        self._products: set[str] | None = None

    replace_release = _Remote._readonly

    def count(self) -> int:
        if self._count is None:
            self._count = int(self._call("count") or 0)
        return self._count

    def products(self) -> set[str]:
        if self._products is None:
            self._products = set(self._call("products") or ())
        return self._products

    def fixes_for(self, product: str) -> list:
        key = product.lower()
        if key not in self._fixes:
            self._fixes[key] = list(self._call("fixes_for", product) or [])
        return self._fixes[key]
