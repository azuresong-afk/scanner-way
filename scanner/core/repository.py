"""Репозиторий: сохранение и чтение прогонов, инвентаря, находок, allowlist.

Функции принимают открытую `Session` и не коммитят сами — границы транзакции
задаёт вызывающий код (`session_scope`). Преобразование ORM <-> доменные модели
(`scanner.core.models`) живёт только здесь.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from scanner.core import coverage as cov
from scanner.core.allowlist import AllowlistGate
from scanner.core.credentials import (
    AUTH_KEY,
    AUTH_KINDS,
    AUTH_PASSWORD,
    BECOME_NONE,
    BECOME_SUDO,
    DB_PROTOCOLS,
    DEFAULT_PORTS,
    PROTOCOL_NETSSH,
    PROTOCOL_SNMP,
    PROTOCOL_SSH,
    PROTOCOL_WINRM,
    CredentialError,
    CredentialVault,
    HostCredential,
    key_fingerprint,
    normalize_scope,
    validate_become,
    validate_cred_set_entries,
    validate_db_name,
    validate_options,
    validate_protocol,
    validate_username,
)
from scanner.core.db import (
    AllowlistEntry,
    CredAuditSetRow,
    Engagement,
    FalsePositiveRow,
    FindingRow,
    HostCredentialRow,
    HostPackageRow,
    HostResult,
    RunCoverageRow,
    ScanRun,
    ServiceResult,
    User,
)
from scanner.core.models import (
    FalsePositiveMark,
    Finding,
    FindingStatus,
    FindingType,
    HostInventory,
    HostOs,
    InstalledPackage,
    ServiceInfo,
    Severity,
)
from scanner.core.osfamily import GENERIC_LINUX, SOURCE_RANK, family_label, is_distro
from scanner.core.osfamily import UNKNOWN as UNKNOWN_OS
from scanner.core.osfamily import classify as classify_os
from scanner.core.targetspec import parse_target

RUN_STATUSES = {"pending", "running", "done", "partial", "failed", "stopped",
                "interrupted"}
# Итоговые статусы: прогон больше не исполняется. interrupted — процесс,
# который вёл прогон, остановился посреди работы (миграция 0017).
FINISHED_RUN_STATUSES = frozenset({"done", "partial", "failed", "stopped", "interrupted"})
# Прогоны, результат которых годится как база сравнения: завершены штатно
# (partial — тоже: сравнение идёт только по реально проверенному, см. coverage).
COMPARABLE_RUN_STATUSES = frozenset({"done", "partial"})
ACTIVE_RUN_STATUSES = frozenset({"pending", "running"})


# ========== Engagement + allowlist ==========
def create_engagement(session: Session, *, name: str, client: str | None = None,
                      contract_ref: str | None = None,
                      created_by: int | None = None) -> int:
    e = Engagement(name=name, client=client, contract_ref=contract_ref,
                   created_by=created_by)
    session.add(e)
    session.flush()
    return e.id


class AllowlistDuplicate(Exception):
    """Цель уже есть в allowlist: та же запись или входит в более широкую подсеть."""

    def __init__(self, cidr: str, existing_id: int, existing_cidr: str):
        self.cidr = cidr
        self.existing_id = existing_id
        self.existing_cidr = existing_cidr
        self.exact = cidr == existing_cidr
        super().__init__(f"{cidr} already covered by {existing_cidr}")


def find_allowlist_cover(session: Session, engagement_id: int,
                         net: ipaddress.IPv4Network | ipaddress.IPv6Network
                         ) -> tuple[int, str] | None:
    """Запись allowlist, совпадающая с `net` или целиком его включающая."""
    rows = session.execute(
        select(AllowlistEntry.id, AllowlistEntry.cidr)
        .where(AllowlistEntry.engagement_id == engagement_id)
        .order_by(AllowlistEntry.id)).all()
    covers = []
    for entry_id, raw in rows:
        existing = ipaddress.ip_network(str(raw), strict=False)
        if existing.version == net.version and net.subnet_of(existing):
            covers.append((existing.prefixlen != net.prefixlen, entry_id, str(existing)))
    if not covers:
        return None
    _, entry_id, existing_cidr = min(covers)   # точное совпадение — первым
    return entry_id, existing_cidr


def add_allowlist_entry(session: Session, *, engagement_id: int, cidr: str,
                        note: str | None = None, added_by: int | None = None) -> int:
    """Добавить цель в allowlist договора. CIDR валидируется и нормализуется.

    Дубли не заносятся: `10.0.0.5`, `10.0.0.5/32` и ` 10.0.0.5 ` — одна цель,
    `10.0.0.7/24` — то же, что `10.0.0.0/24`; адрес или подсеть, уже входящие
    в занесённую подсеть, тоже отклоняются (AllowlistDuplicate).
    """
    net = ipaddress.ip_network(cidr.strip(), strict=False)  # ValueError на мусоре
    cover = find_allowlist_cover(session, engagement_id, net)
    if cover is not None:
        raise AllowlistDuplicate(str(net), *cover)
    entry = AllowlistEntry(engagement_id=engagement_id, cidr=str(net), note=note,
                           added_by=added_by)
    session.add(entry)
    session.flush()
    return entry.id


@dataclass(slots=True)
class AllowlistBulkResult:
    """Итог массового добавления: занесённые записи и пропущенные дубли."""
    added_ids: list[int] = field(default_factory=list)
    # (запись, причина, покрывающая подсеть): duplicate — уже в allowlist целиком
    skipped: list[tuple[str, str, str | None]] = field(default_factory=list)
    # части диапазонов, уже покрытые allowlist (диапазон занесён не целиком)
    partial: list[tuple[str, int]] = field(default_factory=list)


def add_allowlist_specs(session: Session, *, engagement_id: int, specs: Iterable[str],
                        note: str | None = None, added_by: int | None = None
                        ) -> AllowlistBulkResult:
    """Добавить в allowlist адреса, подсети и диапазоны одним действием.

    Диапазон раскладывается в подсети (ровно те же адреса); каждая подсеть
    помечается исходным диапазоном (range_spec). Записи, уже целиком
    покрытые allowlist, пропускаются — повторное добавление ничего не
    расширяет. Мусор — ValueError до любых изменений (всё или ничего).
    """
    parsed = []
    for raw in specs:
        if raw.strip():
            parsed.append(parse_target(raw))      # ValueError на мусоре/имени хоста
    result = AllowlistBulkResult()
    seen: set[str] = set()
    for spec in parsed:
        if spec.text in seen:
            continue
        seen.add(spec.text)
        pending = []
        for net in spec.networks:
            if find_allowlist_cover(session, engagement_id, net) is None:
                pending.append(net)
        if not pending:
            cover = find_allowlist_cover(session, engagement_id, spec.networks[0])
            result.skipped.append((spec.text, "duplicate", cover[1] if cover else None))
            continue
        if len(pending) < len(spec.networks):
            result.partial.append((spec.text, len(spec.networks) - len(pending)))
        for net in pending:
            entry = AllowlistEntry(engagement_id=engagement_id, cidr=str(net), note=note,
                                   added_by=added_by,
                                   range_spec=spec.text if spec.is_range else None)
            session.add(entry)
            session.flush()
            result.added_ids.append(entry.id)
    return result


def remove_allowlist_range(session: Session, engagement_id: int, range_spec: str) -> list[str]:
    """Удалить все подсети диапазона. Возвращает удалённые CIDR."""
    rows = list(session.scalars(select(AllowlistEntry).where(
        AllowlistEntry.engagement_id == engagement_id,
        AllowlistEntry.range_spec == range_spec)))
    cidrs = [str(r.cidr) for r in rows]
    for r in rows:
        session.delete(r)
    return cidrs


def list_allowlist(session: Session, engagement_id: int) -> list[str]:
    rows = session.scalars(
        select(AllowlistEntry.cidr)
        .where(AllowlistEntry.engagement_id == engagement_id)
        .order_by(AllowlistEntry.id))
    return [str(c) for c in rows]


def load_allowlist_gate(session: Session, engagement_id: int) -> AllowlistGate:
    """AllowlistGate из БД. Пустой allowlist = запрещено всё."""
    return AllowlistGate(list_allowlist(session, engagement_id))


# ========== Учётные записи активов ==========
def create_host_credential(session: Session, vault: CredentialVault, *,
                           engagement_id: int, name: str, auth: str, username: str,
                           port: int | None = None, targets: Iterable[str] = (),
                           password: str | None = None, private_key: str | None = None,
                           passphrase: str | None = None,
                           created_by: int | None = None,
                           become: str = BECOME_SUDO,
                           protocol: str = PROTOCOL_SSH,
                           options: dict | None = None,
                           db_name: str | None = None) -> int:
    """Завести учётку договора. Секреты шифруются, в БД открытым текстом не попадают.

    Область действия (targets) обязана входить в allowlist договора: учётка не
    должна «расширять» объём работ. CredentialError — недопустимые данные.
    port=None — стандартный порт протокола (SSH 22, WinRM HTTPS 5986, SNMP 161).
    Учётка WinRM — только по паролю (NTLM), повышения прав у неё нет.
    Учётки сетевого оборудования: netssh — пароль или ключ, без повышения прав
    (уровень доступа задаётся на устройстве: только просмотр); snmp — секрет в
    password (community v2c или ключ аутентификации v3) и passphrase (ключ
    шифрования v3), параметры — в options.
    Учётка СУБД (postgresql/mysql/mssql/oracle) — только по паролю, без повышения
    прав; db_name — база для входа или имя сервиса Oracle.
    """
    protocol = validate_protocol(protocol)
    options = validate_options(protocol, options)
    if auth not in AUTH_KINDS:
        raise CredentialError(f"неизвестный способ аутентификации: {auth}")
    if port is None:
        port = DEFAULT_PORTS[protocol]
    if not 0 < port < 65536:
        raise CredentialError(f"недопустимый порт: {port}")
    if protocol == PROTOCOL_WINRM:
        if auth != AUTH_PASSWORD:
            raise CredentialError("учётка WinRM входит только по паролю (NTLM)")
        become = BECOME_NONE
    if protocol == PROTOCOL_NETSSH:
        become = BECOME_NONE
    if protocol == PROTOCOL_SNMP:
        if auth != AUTH_PASSWORD:
            raise CredentialError("учётка SNMP задаётся community или ключами SNMPv3")
        become = BECOME_NONE
        if options["snmp_version"] == "2c":
            username = username or "community"
        else:
            if options["priv_proto"] != "none" and not passphrase:
                raise CredentialError("SNMPv3: нужен ключ шифрования (priv) — или "
                                      "выберите шифрование «none» (не рекомендуется)")
            for label, value in (("аутентификации", password),
                                 ("шифрования", passphrase)):
                if value and len(value) < 8:
                    raise CredentialError(f"SNMPv3: ключ {label} короче 8 символов")
    if protocol in DB_PROTOCOLS:
        if auth != AUTH_PASSWORD:
            raise CredentialError("учётка СУБД входит только по паролю")
        become = BECOME_NONE
    db_name = validate_db_name(protocol, db_name)
    username = validate_username(username)
    become = validate_become(become)
    scope = normalize_scope(targets)
    for cidr in scope:
        net = ipaddress.ip_network(cidr)
        if find_allowlist_cover(session, engagement_id, net) is None:
            raise CredentialError(f"{cidr} не входит в allowlist договора")
    fingerprint = None
    if auth == AUTH_PASSWORD:
        if not password:
            raise CredentialError("нужен community SNMP" if protocol == PROTOCOL_SNMP
                                  and options["snmp_version"] == "2c" else
                                  "нужен ключ аутентификации SNMPv3"
                                  if protocol == PROTOCOL_SNMP else "нужен пароль")
        secrets = {"password": password}
        if protocol == PROTOCOL_SNMP and options["snmp_version"] == "3" and passphrase:
            secrets["passphrase"] = passphrase
    else:
        if not private_key or not private_key.strip():
            raise CredentialError("нужен закрытый ключ SSH")
        private_key = private_key.strip() + "\n"
        fingerprint = key_fingerprint(private_key, passphrase)
        secrets = {"private_key": private_key, "passphrase": passphrase}
    row = HostCredentialRow(engagement_id=engagement_id, name=name.strip(), auth=auth,
                            username=username, port=port, targets=scope,
                            secret_enc=vault.encrypt(secrets),
                            key_fingerprint=fingerprint, created_by=created_by,
                            become=become, protocol=protocol, options=options,
                            db_name=db_name)
    session.add(row)
    session.flush()
    return row.id


def list_host_credentials(session: Session, engagement_id: int) -> list[HostCredentialRow]:
    return list(session.scalars(
        select(HostCredentialRow).where(HostCredentialRow.engagement_id == engagement_id)
        .order_by(HostCredentialRow.id)))


def load_host_credentials(session: Session, vault: CredentialVault, engagement_id: int,
                          ids: Iterable[int]) -> list[HostCredential]:
    """Расшифрованные учётки прогона (только этого договора), в порядке ids."""
    wanted = list(dict.fromkeys(int(i) for i in ids))
    if not wanted:
        return []
    rows = {r.id: r for r in session.scalars(
        select(HostCredentialRow).where(HostCredentialRow.id.in_(wanted),
                                        HostCredentialRow.engagement_id == engagement_id))}
    out = []
    for cid in wanted:
        r = rows.get(cid)
        if r is None:
            continue
        sec = vault.decrypt(r.secret_enc)
        out.append(HostCredential(
            id=r.id, name=r.name, auth=r.auth, username=r.username, port=r.port,
            targets=tuple(str(t) for t in r.targets or ()),
            password=sec.get("password") if r.auth == AUTH_PASSWORD else None,
            private_key=sec.get("private_key") if r.auth == AUTH_KEY else None,
            passphrase=(sec.get("passphrase")
                        if r.auth == AUTH_KEY or r.protocol == PROTOCOL_SNMP else None),
            become=r.become or BECOME_SUDO, protocol=r.protocol or PROTOCOL_SSH,
            options=dict(r.options or {}), db_name=getattr(r, "db_name", None)))
    return out


# ========== Наборы проверки учёток (аудит паролей) ==========
# Поддерживаемые сервисы — из модуля cred_audit (единый источник истины).
def _supported_services() -> frozenset[str]:
    from scanner.modules.cred_audit import SUPPORTED_SERVICES
    return SUPPORTED_SERVICES


def create_cred_audit_set(session: Session, vault: CredentialVault, *,
                          engagement_id: int, name: str,
                          entries: Iterable[tuple[str, str]],
                          services: Iterable[str] = (),
                          created_by: int | None = None) -> int:
    """Завести набор проверки учёток. Секреты шифруются, открытым текстом не хранятся.

    CredentialError — недопустимые данные (пустой набор, превышение лимита,
    неизвестный сервис).
    """
    pairs = validate_cred_set_entries(entries)
    svc = []
    for s in services:
        s = s.strip().lower()
        if not s:
            continue
        if s not in _supported_services():
            raise CredentialError(f"неподдерживаемый сервис: {s}")
        if s not in svc:
            svc.append(s)
    row = CredAuditSetRow(engagement_id=engagement_id, name=name.strip(),
                          services=svc, secret_enc=vault.encrypt_entries(pairs),
                          entry_count=len(pairs), created_by=created_by)
    session.add(row)
    session.flush()
    return row.id


def list_cred_audit_sets(session: Session, engagement_id: int) -> list[CredAuditSetRow]:
    return list(session.scalars(
        select(CredAuditSetRow).where(CredAuditSetRow.engagement_id == engagement_id)
        .order_by(CredAuditSetRow.id)))


def get_cred_audit_set(session: Session, engagement_id: int,
                       set_id: int) -> CredAuditSetRow | None:
    row = session.get(CredAuditSetRow, set_id)
    return row if row is not None and row.engagement_id == engagement_id else None


def cred_set_masked_usernames(vault: CredentialVault, row: CredAuditSetRow,
                              limit: int = 20) -> list[str]:
    """Маскированные логины набора для выдачи наружу (секреты не раскрываются)."""
    from scanner.core.credentials import mask_username
    seen: list[str] = []
    for username, _ in vault.decrypt_entries(row.secret_enc):
        m = mask_username(username)
        if m not in seen:
            seen.append(m)
        if len(seen) >= limit:
            break
    return seen


def load_cred_set_entries(session: Session, vault: CredentialVault, engagement_id: int,
                          ids: Iterable[int]) -> list[tuple[str, str]]:
    """Расшифрованные пары логин/секрет выбранных наборов (только этого договора).

    Дубликаты (логин, секрет) между наборами убираются."""
    wanted = list(dict.fromkeys(int(i) for i in ids))
    if not wanted:
        return []
    rows = {r.id: r for r in session.scalars(
        select(CredAuditSetRow).where(CredAuditSetRow.id.in_(wanted),
                                      CredAuditSetRow.engagement_id == engagement_id))}
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for sid in wanted:
        r = rows.get(sid)
        if r is None:
            continue
        for pair in vault.decrypt_entries(r.secret_enc):
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
    return out


# ========== Прогоны ==========
def create_scan_run(session: Session, *, engagement_id: int, modules: list[str],
                    rate_profile: str = "gentle", started_by: int | None = None,
                    credential_ids: Iterable[int] = (),
                    cred_set_ids: Iterable[int] = (), name: str | None = None,
                    targets: Iterable[str] = (), schedule_id: int | None = None,
                    retry_of: int | None = None, worker_id: str | None = None,
                    options: Mapping[str, object] | None = None) -> int:
    run = ScanRun(options=dict(options or {}), engagement_id=engagement_id, modules=list(modules),
                  rate_profile=rate_profile, started_by=started_by, status="pending",
                  credential_ids=[int(i) for i in credential_ids],
                  cred_set_ids=[int(i) for i in cred_set_ids], name=name,
                  targets=list(targets), schedule_id=schedule_id, retry_of=retry_of,
                  worker_id=worker_id,
                  heartbeat_at=None if worker_id is None else datetime.now(UTC))
    session.add(run)
    session.flush()
    return run.id


def set_scan_run_status(session: Session, scan_run_id: int, status: str,
                        error_message: str | None = None) -> None:
    """Статус прогона; error_message — причина ошибки/прерывания для
    пользователя (сохраняется, только если передана)."""
    if status not in RUN_STATUSES:
        raise ValueError(f"unknown scan run status: {status}")
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        raise LookupError(f"scan_run {scan_run_id} not found")
    now = datetime.now(UTC)
    run.status = status
    if status == "running" and run.started_at is None:
        run.started_at = now
    if status in FINISHED_RUN_STATUSES:
        run.finished_at = now
    if error_message is not None:
        run.error_message = error_message[:2000]
    session.flush()


def claim_scan_run(session: Session, scan_run_id: int, worker_id: str) -> bool:
    """Атомарно pending -> running за процессом worker_id.

    Условный UPDATE: если прогон уже взял другой исполнитель (или его
    остановили), строка не меняется и возвращается False — так один прогон не
    исполняется дважды, даже если его поставили в очередь повторно."""
    now = datetime.now(UTC)
    res = session.execute(
        update(ScanRun)
        .where(ScanRun.id == scan_run_id, ScanRun.status == "pending")
        .values(status="running", worker_id=worker_id, heartbeat_at=now,
                started_at=func.coalesce(ScanRun.started_at, now))
        .execution_options(synchronize_session=False))
    session.flush()
    return res.rowcount == 1


def set_scan_run_progress(session: Session, scan_run_id: int, progress: dict | None) -> None:
    """Снимок хода прогона (scanner.core.orchestrator.RunProgress). Пишется
    только у активного прогона — остановленный или завершённый не трогаем."""
    session.execute(
        update(ScanRun)
        .where(ScanRun.id == scan_run_id, ScanRun.status.in_(ACTIVE_RUN_STATUSES))
        .values(progress=progress)
        .execution_options(synchronize_session=False))


def recent_run_progress(session: Session, *, engagement_id: int, before_id: int,
                        rate_profile: str | None = None, limit: int = 10) -> list[dict]:
    """Снимки прогресса последних завершённых прогонов проекта (новые первыми;
    с тем же профилем нагрузки — раньше остальных): по ним оценивается, сколько
    займут этапы нового прогона."""
    rows = session.execute(
        select(ScanRun.progress, ScanRun.rate_profile)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.id < before_id,
               ScanRun.status.in_(("done", "partial")), ScanRun.progress.is_not(None))
        .order_by(ScanRun.id.desc()).limit(limit)).all()
    same = [p for p, rp in rows if rp == rate_profile]
    other = [p for p, rp in rows if rp != rate_profile]
    return [p for p in same + other if isinstance(p, dict)]


def touch_scan_runs(session: Session, run_ids: Iterable[int], worker_id: str) -> int:
    """Отметка «жив» для активных прогонов, которые ведёт этот процесс."""
    ids = list(run_ids)
    if not ids:
        return 0
    res = session.execute(
        update(ScanRun)
        .where(ScanRun.id.in_(ids), ScanRun.worker_id == worker_id,
               ScanRun.status.in_(ACTIVE_RUN_STATUSES))
        .values(heartbeat_at=datetime.now(UTC))
        .execution_options(synchronize_session=False))
    return res.rowcount


def active_scan_runs(session: Session) -> list[ScanRun]:
    """Прогоны pending/running — кандидаты для сторожа осиротевших прогонов."""
    return list(session.scalars(select(ScanRun)
                                .where(ScanRun.status.in_(ACTIVE_RUN_STATUSES))
                                .order_by(ScanRun.id)))


def clear_scan_run_results(session: Session, scan_run_id: int) -> None:
    """Удалить результаты прогона перед их записью.

    Результаты пишутся одной транзакцией вместе с этой очисткой, поэтому
    повторное исполнение того же прогона заменяет его строки, а не дублирует.
    Сервисы и пакеты удаляются каскадом вместе с host_results."""
    session.execute(delete(FindingRow).where(FindingRow.scan_run_id == scan_run_id))
    session.execute(delete(RunCoverageRow).where(RunCoverageRow.scan_run_id == scan_run_id))
    session.execute(delete(HostPackageRow).where(HostPackageRow.scan_run_id == scan_run_id))
    host_ids = select(HostResult.id).where(HostResult.scan_run_id == scan_run_id)
    session.execute(delete(ServiceResult).where(ServiceResult.host_id.in_(host_ids)))
    session.execute(delete(HostResult).where(HostResult.scan_run_id == scan_run_id))
    session.flush()


def get_scan_run(session: Session, scan_run_id: int) -> ScanRun | None:
    return session.get(ScanRun, scan_run_id)


def previous_scan_run_id(session: Session, scan_run_id: int, *,
                         coverage: cov.Coverage | None = None,
                         lookback: int = 20) -> int | None:
    """База сравнения: последний более ранний завершённый (done/partial) прогон
    того же договора, у которого есть общие с этим прогоном проверенные пары
    (хост, модуль). Прогон по другим хостам или другим модулям базой не
    становится — иначе всё «исправлено»/«новое» было бы ложным.

    coverage — покрытие этого прогона (если ещё не сохранено в БД)."""
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        return None
    candidates = list(session.scalars(
        select(ScanRun)
        .where(ScanRun.engagement_id == run.engagement_id,
               ScanRun.id < run.id, ScanRun.status.in_(COMPARABLE_RUN_STATUSES))
        .order_by(ScanRun.id.desc())
        .limit(lookback)))
    if not candidates:
        return None
    current = coverage if coverage is not None else run_coverage(session, run)
    if not current:
        return candidates[0].id
    for cand in candidates:
        if cov.comparability(run_coverage(session, cand), current).level != "none":
            return cand.id
    return None


def comparison_baseline(session: Session, run: ScanRun, baseline_id: int) -> ScanRun:
    """Прогон, выбранный для сравнения в отчёте.

    Годится только успешно завершённый (done) более ранний прогон того же договора:
    остановленный или упавший прогон неполон, и «закрытые» в нём были бы ложными.
    """
    base = session.get(ScanRun, baseline_id)
    if base is None or base.engagement_id != run.engagement_id:
        raise ValueError(f"прогон {baseline_id} не найден в договоре")
    if base.id >= run.id:
        raise ValueError("сравнивать можно только с более ранним прогоном")
    if base.status not in COMPARABLE_RUN_STATUSES:
        raise ValueError(f"прогон {baseline_id} в статусе {base.status}; "
                         "для сравнения нужен завершённый прогон (выполнен или частично)")
    return base


# ========== Покрытие прогона ==========
def save_coverage(session: Session, scan_run_id: int, coverage: cov.Coverage) -> int:
    n = 0
    for e in coverage.entries():
        try:
            host = str(ipaddress.ip_address(e.host))
        except ValueError:
            continue
        session.add(RunCoverageRow(scan_run_id=scan_run_id, host=host, module=e.module,
                                   status=e.status, reason=e.reason))
        n += 1
    session.flush()
    return n


def run_coverage(session: Session, run: ScanRun | int) -> cov.Coverage:
    """Покрытие прогона; у прогонов до миграции 0020 — оценка по хостам
    discovery и модулям прогона (coverage.legacy_coverage)."""
    if not isinstance(run, ScanRun):
        run = session.get(ScanRun, run)
        if run is None:
            return cov.Coverage()
    rows = list(session.scalars(select(RunCoverageRow)
                                .where(RunCoverageRow.scan_run_id == run.id)))
    if rows:
        return cov.coverage_from_rows(rows)
    hosts = {str(h) for h in session.scalars(select(HostResult.host)
                                             .where(HostResult.scan_run_id == run.id))}
    hosts |= {str(h) for h in session.scalars(select(FindingRow.host).distinct()
                                              .where(FindingRow.scan_run_id == run.id))}
    return cov.legacy_coverage(run.status, list(run.modules or []),
                               list(run.targets or []), hosts)


def set_run_warnings(session: Session, scan_run_id: int, warnings: list[dict]) -> None:
    run = session.get(ScanRun, scan_run_id)
    if run is not None:
        run.warnings = list(warnings)
        session.flush()


# ========== Инвентарь ==========
def save_host(session: Session, *, scan_run_id: int, host: str, state: str | None = "up",
              os_guess: str | None = None, os_accuracy: int | None = None,
              os_family: str | None = None, os_source: str | None = None) -> int:
    h = HostResult(scan_run_id=scan_run_id, host=str(ipaddress.ip_address(host)),
                   state=state, os_guess=os_guess, os_accuracy=os_accuracy,
                   os_family=os_family, os_source=os_source)
    session.add(h)
    session.flush()
    return h.id


def save_hosts(session: Session, *, scan_run_id: int, hosts: Iterable[HostOs]) -> int:
    """Сохранить живые хосты discovery с их ОС (до сервисов и инвентаризации)."""
    n = 0
    for h in hosts:
        save_host(session, scan_run_id=scan_run_id, host=h.host, os_guess=h.name,
                  os_accuracy=h.accuracy, os_family=h.family, os_source=h.source)
        n += 1
    return n


def save_services(session: Session, *, scan_run_id: int,
                  services: Iterable[ServiceInfo]) -> dict[str, int]:
    """Сохранить сервисы; host_results создаются по необходимости.

    Возвращает {host: host_result_id}.
    """
    existing = {
        str(h.host): h.id for h in session.scalars(
            select(HostResult).where(HostResult.scan_run_id == scan_run_id))
    }
    for s in services:
        host = str(ipaddress.ip_address(s.host))
        if host not in existing:
            existing[host] = save_host(session, scan_run_id=scan_run_id, host=host)
        session.add(ServiceResult(host_id=existing[host], port=s.port,
                                  protocol=s.protocol, service=s.service,
                                  product=s.product, version=s.version, cpe=s.cpe))
    session.flush()
    return existing


def save_inventory(session: Session, *, scan_run_id: int,
                   inventories: Iterable[HostInventory]) -> int:
    """Сохранить результат инвентаризации по учётке: ОС хоста и пакеты.

    ОС, прочитанная на самом хосте, точнее догадки nmap — она заменяет os_guess.
    Возвращает число сохранённых пакетов.
    """
    hosts = {str(h.host): h for h in session.scalars(
        select(HostResult).where(HostResult.scan_run_id == scan_run_id))}
    n = 0
    for inv in inventories:
        host = str(ipaddress.ip_address(inv.host))
        h = hosts.get(host)
        if h is None:
            h = session.get(HostResult, save_host(session, scan_run_id=scan_run_id,
                                                  host=host))
            hosts[host] = h
        if inv.os_label:
            h.os_guess, h.os_accuracy = inv.os_label, 100
            h.os_family, h.os_source = inv.os_family, "ssh"
        for p in inv.packages:
            session.add(HostPackageRow(scan_run_id=scan_run_id, host=host,
                                       manager=p.manager, name=p.name,
                                       version=p.version, arch=p.arch))
            n += 1
    session.flush()
    return n


def get_packages(session: Session, scan_run_id: int,
                 host: str | None = None) -> list[tuple[str, InstalledPackage]]:
    """[(host, пакет)] прогона, по хосту и имени пакета."""
    q = select(HostPackageRow).where(HostPackageRow.scan_run_id == scan_run_id)
    if host is not None:
        q = q.where(HostPackageRow.host == str(ipaddress.ip_address(host)))
    rows = [(str(r.host), InstalledPackage(r.name, r.version, r.manager, r.arch))
            for r in session.scalars(q.order_by(HostPackageRow.id))]
    rows.sort(key=lambda x: (int(ipaddress.ip_address(x[0])), x[1].name, x[1].version))
    return rows


def get_services(session: Session, scan_run_id: int) -> list[ServiceInfo]:
    rows = session.execute(
        select(HostResult.host, ServiceResult)
        .join(ServiceResult, ServiceResult.host_id == HostResult.id)
        .where(HostResult.scan_run_id == scan_run_id)
        .order_by(ServiceResult.id))
    return [ServiceInfo(host=str(host), port=s.port, protocol=s.protocol,
                        service=s.service, product=s.product, version=s.version,
                        cpe=s.cpe)
            for host, s in rows]


def _host_os(h: HostResult) -> dict:
    """ОС из строки host_results; у строк до миграции 0007 — выводится из os_guess."""
    source = h.os_source or ("ssh" if h.os_accuracy == 100 else "nmap")
    family = h.os_family or classify_os(h.os_guess)
    return {"name": h.os_guess, "family": family, "source": source,
            "accuracy": h.os_accuracy, "run_id": h.scan_run_id}


def _replaces_os(cur: dict | None, new: dict) -> bool:
    """Заменяет ли ОС из более позднего прогона уже известную.

    Новые данные побеждают, если они не менее точны по источнику. Менее точные
    (nmap после SSH) не затирают дистрибутив, если ничем им не противоречат:
    «Linux 4.15» после «Astra Linux 1.7» оставляет Astra. Если же nmap увидел
    другое семейство (хост переустановили под Windows) — берётся новое.
    """
    if cur is None:
        return True
    if SOURCE_RANK.get(new["source"], 0) >= SOURCE_RANK.get(cur["source"], 0):
        return True
    return new["family"] not in (None, cur["family"]) and not (
        new["family"] == GENERIC_LINUX and is_distro(cur["family"]))


def engagement_hosts(session: Session, engagement_id: int,
                     os_family: str | None = None) -> list[dict]:
    """Инвентарь договора: все хосты, встречавшиеся в любом прогоне.

    Хост попадает в инвентарь по результатам discovery (host_results) или по
    находкам. Сервисы и ОС — из последнего прогона, где они были. Для каждого
    хоста — список прогонов, в которых он встречался (`run_ids`, по возрастанию).
    ОС — самая точная из известных (см. `_replaces_os`), с семейством `os_family`;
    `os_family` в аргументах оставляет только хосты этого семейства
    («unknown» — хосты без определённой ОС).
    """
    run_ids = list(session.scalars(
        select(ScanRun.id).where(ScanRun.engagement_id == engagement_id)))
    if not run_ids:
        return []
    hosts: dict[str, dict] = {}

    def get(host: object) -> dict:
        key = str(ipaddress.ip_address(str(host).split("/")[0]))
        if key not in hosts:
            hosts[key] = {"host": key, "os_guess": None, "run_ids": set(),
                          "services": [], "services_run_id": None, "os": None}
        return hosts[key]

    for h in session.scalars(select(HostResult).where(HostResult.scan_run_id.in_(run_ids))
                             .order_by(HostResult.scan_run_id, HostResult.id)):
        row = get(h.host)
        row["run_ids"].add(h.scan_run_id)
        if h.os_guess or h.os_family:
            new = _host_os(h)
            if _replaces_os(row["os"], new):
                row["os"] = new
    for host, rid in session.execute(
            select(FindingRow.host, FindingRow.scan_run_id).distinct()
            .where(FindingRow.scan_run_id.in_(run_ids))):
        get(host)["run_ids"].add(rid)
    rows = session.execute(
        select(HostResult.host, HostResult.scan_run_id, ServiceResult)
        .join(ServiceResult, ServiceResult.host_id == HostResult.id)
        .where(HostResult.scan_run_id.in_(run_ids))
        .order_by(HostResult.scan_run_id.desc(), ServiceResult.id))
    for host, rid, s in rows:
        row = get(host)
        if row["services_run_id"] is None:
            row["services_run_id"] = rid
        if row["services_run_id"] == rid:
            row["services"].append(ServiceInfo(
                host=row["host"], port=s.port, protocol=s.protocol, service=s.service,
                product=s.product, version=s.version, cpe=s.cpe))
    for host, rid, count in session.execute(
            select(HostPackageRow.host, HostPackageRow.scan_run_id, func.count())
            .where(HostPackageRow.scan_run_id.in_(run_ids))
            .group_by(HostPackageRow.host, HostPackageRow.scan_run_id)
            .order_by(HostPackageRow.scan_run_id.desc())):
        row = get(host)
        row["run_ids"].add(rid)
        if row.get("packages_run_id") is None:
            row["packages_run_id"], row["package_count"] = rid, count
    out = []
    for row in hosts.values():
        os_ = row.pop("os") or {}
        row["os_guess"] = os_.get("name")
        row["os_family"] = os_.get("family")
        row["os_family_label"] = family_label(os_.get("family"))
        row["os_source"] = os_.get("source")
        row["os_accuracy"] = os_.get("accuracy")
        row["os_run_id"] = os_.get("run_id")
        row.setdefault("packages_run_id", None)
        row.setdefault("package_count", 0)
        row["run_ids"] = sorted(row["run_ids"])
        row["services"].sort(key=lambda s: (s.port, s.protocol))
        if os_family is None or (row["os_family"] or UNKNOWN_OS) == os_family:
            out.append(row)
    return sorted(out, key=lambda r: (ipaddress.ip_address(r["host"]).version,
                                      int(ipaddress.ip_address(r["host"]))))


def host_os_names(session: Session, engagement_id: int) -> dict[str, str]:
    """Адрес -> название ОС (с семейством) по инвентарю договора — для привязки
    рекомендаций отчёта к дистрибутиву хоста."""
    out = {}
    for row in engagement_hosts(session, engagement_id):
        if row["os_family"] and row["os_family"] != UNKNOWN_OS:
            out[row["host"]] = " ".join(x for x in (row["os_family_label"], row["os_guess"])
                                        if x)
    return out


# ========== Находки ==========
def save_findings(session: Session, *, engagement_id: int, scan_run_id: int,
                  findings: Iterable[Finding],
                  statuses: Mapping[str, FindingStatus | str] | None = None) -> int:
    """Сохранить находки прогона. statuses — {dedup_key: status} из diff_runs."""
    statuses = statuses or {}
    n = 0
    for f in findings:
        key = f.dedup_key()
        session.add(FindingRow(
            engagement_id=engagement_id, scan_run_id=scan_run_id,
            module=f.module, finding_type=str(f.finding_type),
            host=str(ipaddress.ip_address(f.host)), port=f.port, vuln_id=f.vuln_id,
            cve_ids=list(f.cve_ids), bdu_ids=list(f.bdu_ids), title=f.title,
            severity=str(f.severity),
            cvss=None if f.cvss is None else Decimal(str(f.cvss)),
            evidence=f.evidence, status=str(statuses.get(key, FindingStatus.OPEN)),
            dedup_key=key, detected_at=_aware(f.detected_at),
            remediation=f.remediation, confidence=f.confidence, source=f.source))
        n += 1
    session.flush()
    return n


def row_to_finding(r: FindingRow) -> Finding:
    return Finding(
        module=r.module, host=str(r.host), finding_type=FindingType(r.finding_type),
        title=r.title, severity=Severity(r.severity), port=r.port, vuln_id=r.vuln_id,
        cve_ids=list(r.cve_ids or []), bdu_ids=list(r.bdu_ids or []),
        cvss=None if r.cvss is None else float(r.cvss), evidence=r.evidence,
        detected_at=r.detected_at, remediation=r.remediation,
        confidence=r.confidence, source=r.source)


def get_findings(session: Session, scan_run_id: int,
                 module: str | None = None) -> list[Finding]:
    """Находки прогона (опционально — одного модуля) для diff/отчётов."""
    return [row_to_finding(r) for r in get_finding_rows(session, scan_run_id, module)]


def get_finding_rows(session: Session, scan_run_id: int,
                     module: str | None = None) -> list[FindingRow]:
    """Строки находок прогона (с id и dedup_key — для API)."""
    q = select(FindingRow).where(FindingRow.scan_run_id == scan_run_id)
    if module is not None:
        q = q.where(FindingRow.module == module)
    return list(session.scalars(q.order_by(FindingRow.id)))


def get_finding_statuses(session: Session, scan_run_id: int) -> dict[str, str]:
    """{dedup_key: status} находок прогона."""
    rows = session.execute(
        select(FindingRow.dedup_key, FindingRow.status)
        .where(FindingRow.scan_run_id == scan_run_id))
    return {k: s for k, s in rows}


def historically_fixed_keys(session: Session, engagement_id: int,
                            before_run_id: int) -> set[str]:
    """Ключи находок, которые когда-либо были в прогонах до before_run_id.

    Используется как historically_fixed в diff_runs: если ключ был раньше, исчез
    и снова появился — это regression. Ключи из непосредственно предыдущего
    прогона diff_runs отработает как open, поэтому пересечение безопасно.
    """
    rows = session.scalars(
        select(FindingRow.dedup_key).distinct()
        .where(FindingRow.engagement_id == engagement_id,
               FindingRow.scan_run_id < before_run_id))
    return set(rows)


def _aware(dt: datetime) -> datetime:
    # Finding.detected_at создаётся через datetime.utcnow() (naive UTC).
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ========== Ложные срабатывания ==========
def false_positive_marks(session: Session,
                         engagement_id: int) -> dict[str, FalsePositiveMark]:
    """{dedup_key: отметка} — действующие отметки «ложное срабатывание» договора."""
    rows = session.execute(
        select(FalsePositiveRow, User.username)
        .outerjoin(User, User.id == FalsePositiveRow.marked_by)
        .where(FalsePositiveRow.engagement_id == engagement_id))
    return {r.dedup_key: FalsePositiveMark(dedup_key=r.dedup_key, reason=r.reason,
                                           marked_by=username,
                                           marked_at=r.marked_at)
            for r, username in rows}


def list_false_positives(session: Session, engagement_id: int) -> list[FalsePositiveRow]:
    return list(session.scalars(
        select(FalsePositiveRow).where(FalsePositiveRow.engagement_id == engagement_id)
        .order_by(FalsePositiveRow.id)))


def mark_false_positive(session: Session, finding: FindingRow, *,
                        reason: str | None, marked_by: int | None) -> FalsePositiveRow:
    """Отметить находку как ложное срабатывание (повторная отметка обновляет
    причину и автора)."""
    row = session.scalar(select(FalsePositiveRow).where(
        FalsePositiveRow.engagement_id == finding.engagement_id,
        FalsePositiveRow.dedup_key == finding.dedup_key))
    if row is None:
        row = FalsePositiveRow(engagement_id=finding.engagement_id,
                               dedup_key=finding.dedup_key)
        session.add(row)
    row.host, row.port, row.vuln_id = finding.host, finding.port, finding.vuln_id
    row.module, row.title = finding.module, finding.title
    row.reason, row.marked_by = reason, marked_by
    row.marked_at = datetime.now(UTC)
    session.flush()
    return row


def unmark_false_positive(session: Session, engagement_id: int,
                          dedup_key: str) -> FalsePositiveRow | None:
    """Снять отметку. Возвращает удалённую отметку или None, если её не было."""
    row = session.scalar(select(FalsePositiveRow).where(
        FalsePositiveRow.engagement_id == engagement_id,
        FalsePositiveRow.dedup_key == dedup_key))
    if row is not None:
        session.delete(row)
        session.flush()
    return row
