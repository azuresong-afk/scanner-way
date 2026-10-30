"""FastAPI-слой: договоры и allowlist, запуск/остановка прогонов, отчёты, RBAC.

Аутентификация — Bearer-токен (`POST /auth/token`). Права проверяются на уровне
API до постановки задач (см. `scanner.api.rbac`). Все действия пользователей
(вход, изменения, запуск/остановка, экспорт отчётов, отказы в доступе) и
сканера пишутся в `audit_log`.

`create_app()` собирает приложение из зависимостей (фабрика сессий, реестр
модулей, исполнитель прогонов) — тесты подставляют SQLite и фиктивные модули.
"""
from __future__ import annotations

import logging
import secrets
from collections.abc import Callable, Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from scanner.api import (
    routes_assets,
    routes_audit,
    routes_auth,
    routes_cred_sets,
    routes_credentials,
    routes_engagements,
    routes_feeds,
    routes_findings,
    routes_reachability,
    routes_runs,
    routes_schedules,
)
from scanner.api.rbac import seed_rbac, set_user_roles
from scanner.api.scheduler import Scheduler
from scanner.api.security import LoginThrottle, TokenSigner, hash_password
from scanner.api.settings import ApiSettings
from scanner.core.audit import AuditSink, DbAuditSink
from scanner.core.credentials import CredentialVault, load_vault
from scanner.core.db import User, make_engine, make_session_factory, session_scope
from scanner.core.models import Finding
from scanner.core.orchestrator import ModuleFactory, RunService
from scanner.core.reachability import CheckThrottle, ReachabilityResult, check_host
from scanner.feeds.scheduler import FeedScheduler, seed_feed_sync
from scanner.feeds.sources import FeedSource
from scanner.reporting.remediation import RemediationResolver

log = logging.getLogger(__name__)

ResolverFactory = Callable[[list[Finding]], RemediationResolver]
ReachabilityCheck = Callable[[str, list[int]], ReachabilityResult]


def bdu_resolver_factory(store) -> ResolverFactory:
    """Рекомендации из справочника БДУ ФСТЭК (feeds.store.ReferenceStore)."""
    def factory(findings: list[Finding]) -> RemediationResolver:
        ids = {b.upper() for f in findings for b in f.bdu_ids}
        ids |= {f.vuln_id.upper() for f in findings
                if f.vuln_id and f.vuln_id.upper().startswith("BDU:")}
        bdu = {}
        for bid in sorted(ids):
            try:
                rec = store.get_bdu(bid)
            except Exception:
                log.warning("BDU reference store is unavailable", exc_info=True)
                break
            if rec is not None:
                bdu[bid] = rec
        return RemediationResolver(bdu=bdu)
    return factory


def bootstrap(session_factory: sessionmaker[Session], settings: ApiSettings,
              audit: AuditSink) -> None:
    """Засеять роли/права; создать первого admin, если пользователей нет."""
    with session_scope(session_factory) as s:
        seed_rbac(s)
        if not (settings.bootstrap_admin and settings.bootstrap_password):
            return
        if s.scalar(select(User.id).limit(1)) is not None:
            return
        u = User(username=settings.bootstrap_admin, display_name="bootstrap admin",
                 password_hash=hash_password(settings.bootstrap_password), is_active=True)
        s.add(u)
        s.flush()
        set_user_roles(s, u.id, ["admin"])
    audit.record(subject="system", action="user_create",
                 target=f"user:{settings.bootstrap_admin}", result="ok",
                 details={"roles": ["admin"], "bootstrap": True})


def create_app(*, session_factory: sessionmaker[Session] | None = None,
               settings: ApiSettings | None = None,
               audit: AuditSink | None = None,
               registry: Mapping[str, ModuleFactory] | None = None,
               executor: Executor | None = None,
               resolver_factory: ResolverFactory | None = None,
               reachability: ReachabilityCheck | None = None,
               vault: CredentialVault | None = None,
               feed_sources: Mapping[str, FeedSource] | None = None,
               feed_executor: Executor | None = None) -> FastAPI:
    settings = settings or ApiSettings()
    if session_factory is None:
        session_factory = make_session_factory(make_engine())
    if resolver_factory is None:
        from scanner.feeds.store import SqlReferenceStore
        resolver_factory = bdu_resolver_factory(
            SqlReferenceStore(session_factory.kw["bind"]))
    audit = audit or DbAuditSink(session_factory)
    secret = settings.secret
    if not secret:
        log.warning("SCANNER_API_SECRET is not set: using an ephemeral token key")
        secret = secrets.token_urlsafe(48)
    own_executor = executor is None
    executor = executor or ThreadPoolExecutor(max_workers=settings.run_workers,
                                              thread_name_prefix="scan-run")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        bootstrap(session_factory, settings, audit)
        seed_feed_sync(session_factory, timezone=settings.timezone,
                       sources=app.state.feed_scheduler.sources)
        app.state.scheduler.start()
        app.state.feed_scheduler.start()
        yield
        app.state.scheduler.stop()
        app.state.feed_scheduler.stop()
        if own_executor:
            executor.shutdown(wait=False, cancel_futures=False)

    app = FastAPI(title="Scanner", version="0.1.0", lifespan=lifespan)
    app.state.sessions = session_factory
    app.state.audit = audit
    app.state.signer = TokenSigner(secret, settings.token_ttl_minutes * 60)
    app.state.throttle = LoginThrottle(settings.login_max_failures,
                                       settings.login_lockout_minutes * 60)
    if vault is None:
        vault = load_vault(settings.credentials_key or settings.secret or None)
    app.state.runs = RunService(session_factory, audit, registry=registry,
                                executor=executor, vault=vault)
    app.state.scheduler = Scheduler(session_factory, app.state.runs, audit,
                                    tick_seconds=settings.scheduler_tick_seconds)
    app.state.feed_scheduler = FeedScheduler(
        session_factory, audit, sources=feed_sources, executor=feed_executor,
        tick_seconds=settings.feeds_tick_seconds)
    app.state.default_timezone = settings.timezone
    app.state.resolver_factory = resolver_factory
    app.state.reach_check = reachability or check_host
    app.state.reach_throttle = CheckThrottle(settings.reachability_per_minute, 60.0)

    # Только явно перечисленные origin'ы; токен передаётся в заголовке
    # Authorization, cookie не используются — allow_credentials не нужен.
    if settings.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list,
                           allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"],
                           expose_headers=["Content-Disposition", "X-Audit-Count"], max_age=600)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(routes_auth.router)
    app.include_router(routes_engagements.router)
    app.include_router(routes_credentials.router)
    app.include_router(routes_assets.router)
    app.include_router(routes_cred_sets.router)
    app.include_router(routes_runs.router)
    app.include_router(routes_findings.router)
    app.include_router(routes_schedules.router)
    app.include_router(routes_feeds.router)
    app.include_router(routes_reachability.router)
    app.include_router(routes_audit.router)
    return app


app = create_app()
