"""Проверка входа по учётным записям активов («Активы» → «Проверить учётки»).

Только вход и выход — без инвентаризации и без команд на хосте
(`scanner.core.credcheck`). Ограничители те же, что у прогона с учётками:

  * права `run_scan` и `host_credentials` (как для модулей auth_inventory /
    win_inventory / config_audit) — admin без них проверить не может;
  * только литеральные IP; каждый адрес — через allowlist договора в момент
    проверки (адрес вне allowlist не трогается и получает not_in_allowlist);
  * частота — не больше `credential_check_hosts_per_minute` хостов на
    пользователя в минуту, не больше 16 хостов за запрос, параллельно —
    `credential_check_workers` хостов, учётки одного хоста — по очереди;
  * в журнал аудита — по записи на каждый хост (и на каждый отказ), без
    секретов: id, имя, логин, протокол, порт и исход каждой учётки.
"""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from scanner.api.deps import AuditDep, Principal, SessionDep, require
from scanner.api.rbac import Perm
from scanner.api.routes_engagements import get_engagement
from scanner.api.schemas import (
    CredentialCheckIn,
    CredentialCheckOut,
    CredentialHostCheckOut,
    CredentialLoginOut,
)
from scanner.core import repository as repo
from scanner.core.credcheck import (
    NOT_IN_ALLOWLIST,
    HostCheck,
    check_host_credentials,
    default_connectors,
)
from scanner.core.credentials import HostCredential, VaultUnavailable

router = APIRouter(tags=["credentials"])

ACTION = "credential_check"


def default_check(host: str, creds: list[HostCredential]) -> HostCheck:
    return check_host_credentials(host, creds, default_connectors())


def _out(r: HostCheck) -> CredentialHostCheckOut:
    return CredentialHostCheckOut(
        host=r.host, status=r.status, message=r.message, elapsed_ms=r.elapsed_ms,
        results=[CredentialLoginOut(
            credential_id=x.credential_id, credential=x.credential, protocol=x.protocol,
            username=x.username, port=x.port, status=x.status, message=x.message,
            elapsed_ms=x.elapsed_ms) for x in r.results])


@router.post("/engagements/{engagement_id}/credential-check",
             response_model=CredentialCheckOut)
def check_credentials(engagement_id: int, body: CredentialCheckIn, request: Request,
                      user: Annotated[Principal, Depends(require(Perm.RUN_SCAN,
                                                                 Perm.HOST_CREDENTIALS))],
                      session: SessionDep, audit: AuditDep) -> CredentialCheckOut:
    get_engagement(session, engagement_id)
    target_ref = f"engagement:{engagement_id}"

    def reject(code: int, result: str, message, **details) -> HTTPException:
        audit.record(subject=user.subject, action=ACTION, target=target_ref,
                     result=result, details={"hosts": body.hosts[:16], **details})
        return HTTPException(code, message)

    hosts: list[str] = []
    for spec in body.hosts:
        try:
            host = str(ipaddress.ip_address(spec.strip()))
        except ValueError:
            # подсети и имена не принимаем: проверка — по конкретным хостам, без DNS
            raise reject(422, "rejected_not_an_ip",
                         "hosts must be single IP addresses") from None
        if host not in hosts:
            hosts.append(host)

    vault = request.app.state.runs.vault
    if vault is None:
        raise reject(status.HTTP_503_SERVICE_UNAVAILABLE, "rejected_no_vault", {
            "code": "credentials_key_missing",
            "message": "не задан ключ шифрования учётных записей: "
                       "SCANNER_CREDENTIALS_KEY (или SCANNER_API_SECRET) в .env"})
    rows = repo.list_host_credentials(session, engagement_id)
    ids = [r.id for r in rows]
    if body.credential_ids is not None:
        wanted = set(body.credential_ids)
        unknown = sorted(wanted - set(ids))
        if unknown:
            raise reject(404, "rejected_unknown_credential",
                         "credential not found", credential_ids=unknown)
        ids = [i for i in ids if i in wanted]
    try:
        creds = repo.load_host_credentials(session, vault, engagement_id, ids)
    except VaultUnavailable as e:
        raise reject(status.HTTP_503_SERVICE_UNAVAILABLE, "rejected_vault_error",
                     str(e)) from e

    # allowlist — в момент проверки, как и у прогона
    gate = repo.load_allowlist_gate(session, engagement_id)
    allowed = [h for h in hosts if gate.is_allowed(h)]
    if allowed and not request.app.state.credcheck_throttle.allow(user.subject,
                                                                  len(allowed)):
        raise reject(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited",
                     "too many credential checks, try again in a minute",
                     count=len(allowed))
    session.commit()   # отпустить транзакцию на время сетевых проверок

    check = request.app.state.cred_check
    results: dict[str, HostCheck] = {}
    if allowed:
        workers = max(1, min(request.app.state.credcheck_workers, len(allowed)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="cred-check") as pool:
            for host, r in zip(allowed, pool.map(lambda h: check(h, creds), allowed),
                               strict=True):
                results[host] = r

    out: list[CredentialHostCheckOut] = []
    for host in hosts:
        r = results.get(host) or HostCheck(
            host, NOT_IN_ALLOWLIST,
            "адрес не входит в allowlist договора — вход не проверялся")
        audit.record(subject=user.subject, action=ACTION, target=target_ref,
                     result=r.status,
                     details={"host": host, "credentials": [
                         {"credential_id": x.credential_id, "credential": x.credential,
                          "user": x.username, "protocol": x.protocol, "port": x.port,
                          "status": x.status} for x in r.results]})
        out.append(_out(r))
    return CredentialCheckOut(hosts=out, checked_at=datetime.now(UTC))
