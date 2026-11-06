"""Автономный режим, сторона центра: выгрузка задания и приём результата.

Жизненный цикл автономного прогона:

    pending  --«Выгрузить задание»-->  running (за узлом, задание exported)
    running  --«Загрузить результат»--> done / partial / … (задание imported)
    running  --«Отменить задание»----> stopped (задание cancelled)
    running  --срок + запас истёк----> failed  (задание expired)

Таблица ``offline_jobs`` (миграция 0029) — одно задание на прогон. В ней
хранится сам файл задания (он уже зашифрован на ключ узла и подписан), чтобы
его можно было скачать повторно, не расшифровывая учётки ещё раз.

Защита при приёме результата:
* подпись узла проверяется по открытому ключу из карточки узла, и это должен
  быть тот же ключ, на который выпускалось задание;
* результат привязан к заданию (id + SHA-256 файла задания) — результат
  другого задания, повторная загрузка и результат отменённого/просроченного
  задания отклоняются;
* данные по адресам вне allowlist договора ∩ сетей узла отбрасываются (как у
  сетевого узла) и отмечаются в аудите (node_result_filtered).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.core import repository as repo
from scanner.core import run_events as ev
from scanner.core.db import Engagement, OfflineJobRow, ScanNode, ScanRun, session_scope
from scanner.nodes import offline_files as of
from scanner.nodes.offline_crypto import (
    ROLE_CENTER,
    ROLE_NODE,
    KeyPair,
    OfflineCryptoError,
    PublicKeys,
    parse_public,
)

MODE_OFFLINE = "offline"
DEFAULT_VALID_DAYS = 14
MAX_VALID_DAYS = 90
# Сколько центр ждёт результат после истечения срока задания: узел мог начать
# задание в последний день, а прогон по сотням хостов идёт часами.
RESULT_GRACE = timedelta(days=3)

STATUS_EXPORTED = "exported"
STATUS_IMPORTED = "imported"
STATUS_CANCELLED = "cancelled"
STATUS_EXPIRED = "expired"
STATUS_LABELS = {STATUS_EXPORTED: "Ожидает результат", STATUS_IMPORTED: "Результат загружен",
                 STATUS_CANCELLED: "Отменено", STATUS_EXPIRED: "Срок истёк"}
MSG_EXPIRED = ("Результат с автономного узла не загружен в срок: задание просрочено. "
               "Повторите прогон и выгрузите новое задание.")


class OfflineError(Exception):
    """Отказ, понятный оператору (API отдаёт 409/422)."""

    def __init__(self, message: str, *, code: str = "offline_error", status: int = 409):
        super().__init__(message)
        self.code = code
        self.status = status


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


# ========== Ключи центра ==========
def center_material(settings) -> str:
    """Секрет ключей центра: SCANNER_OFFLINE_KEY, иначе ключ учёток / API.

    Только заданный в окружении секрет: если SCANNER_API_SECRET пуст, API
    генерирует его при каждом старте, и ключ центра менялся бы с перезапуском."""
    return (getattr(settings, "offline_key", "") or getattr(settings, "credentials_key", "")
            or getattr(settings, "secret", "") or "")


def center_keys(material: str | None) -> KeyPair:
    """Ключи центра из секрета (SCANNER_OFFLINE_KEY, иначе ключ учёток)."""
    if not material or len(material) < 16:
        raise OfflineError("не задан секрет для ключей автономного режима: "
                           "SCANNER_OFFLINE_KEY или SCANNER_CREDENTIALS_KEY/"
                           "SCANNER_API_SECRET (не короче 16 символов)",
                           code="offline_key_missing")
    return KeyPair.derive(ROLE_CENTER, material, purpose="scanner-center")


def node_public(node: ScanNode) -> PublicKeys:
    if not node.public_key:
        raise OfflineError(f"у узла «{node.name}» не загружен открытый ключ: "
                           "«Сканеры» → узел → «Ключ узла»", code="node_key_missing")
    try:
        return parse_public(node.public_key, ROLE_NODE)
    except OfflineCryptoError as e:
        raise OfflineError(f"ключ узла «{node.name}» повреждён: {e}",
                           code="node_key_invalid") from e


def set_node_key(session: Session, node: ScanNode, text: str) -> PublicKeys:
    """Загрузить открытый ключ автономного узла (файл node.pub с узла).

    Смена ключа при невыполненных заданиях запрещена: их результаты были бы
    подписаны прежним ключом и не прошли бы проверку."""
    if node.mode != MODE_OFFLINE:
        raise OfflineError("ключ загружается только для автономного узла",
                           code="node_not_offline")
    try:
        pub = parse_public(text, ROLE_NODE)
    except OfflineCryptoError as e:
        raise OfflineError(f"ключ узла: {e}", code="node_key_invalid", status=422) from e
    if node.public_key and node.public_key.strip() != pub.export():
        pending = session.scalar(select(OfflineJobRow.id).where(
            OfflineJobRow.node_id == node.id, OfflineJobRow.status == STATUS_EXPORTED)
            .limit(1))
        if pending:
            raise OfflineError("у узла есть невыполненные задания — отмените их или "
                               "загрузите результаты, затем меняйте ключ",
                               code="node_has_pending_jobs")
    node.public_key = pub.export()
    return pub


# ========== Выгрузка задания ==========
@dataclass(slots=True)
class ExportedJob:
    job_id: str
    filename: str
    data: bytes
    expires_at: datetime


def job_filename(node_name: str, run_id: int, issued: datetime) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in node_name)[:40]
    return f"job-{safe}-run{run_id}-{issued:%Y%m%d-%H%M}{of.FILE_SUFFIX[of.FORMAT_JOB]}"


def _job_counts(job: Any) -> dict[str, int]:
    """Сводка для открытого заголовка: только счётчики, без адресов и логинов."""
    return {"targets": len(job.targets or []), "credentials": len(job.credentials or []),
            "cred_candidates": len(job.cred_candidates or [])}


def export_job(sessions: sessionmaker[Session], runs, audit, *, run_id: int, actor: str,
               keys: KeyPair, valid_days: int = DEFAULT_VALID_DAYS,
               now: datetime | None = None) -> ExportedJob:
    """Выдать задание автономному узлу: прогон pending -> running за узлом."""
    now = now or _now()
    valid_days = max(1, min(int(valid_days), MAX_VALID_DAYS))
    with session_scope(sessions) as s:
        run = repo.get_scan_run(s, run_id)
        if run is None:
            raise OfflineError("прогон не найден", code="not_found", status=404)
        existing = s.scalar(select(OfflineJobRow).where(OfflineJobRow.run_id == run_id))
        if existing is not None:
            raise OfflineError(f"задание по прогону уже выгружено "
                               f"({STATUS_LABELS.get(existing.status, existing.status)}); "
                               "скачайте его повторно из карточки прогона",
                               code="already_exported")
        node = s.get(ScanNode, run.node_id) if run.node_id else None
        if node is None or node.mode != MODE_OFFLINE:
            raise OfflineError("прогон назначен не на автономный узел",
                               code="node_not_offline")
        if not node.enabled:
            raise OfflineError(f"узел «{node.name}» отключён", code="node_disabled")
        if run.status != "pending":
            raise OfflineError(f"выгрузить можно только прогон в очереди (сейчас: "
                               f"{run.status})", code="run_not_pending")
        recipient = node_public(node)
        node_id, node_name = node.id, node.name
        engagement = s.get(Engagement, run.engagement_id)
        eng_label = (engagement.contract_ref or engagement.name) if engagement else None
        # в открытом заголовке — только номера, узел, сроки и счётчики; имя
        # прогона (в нём адреса) и договор (заказчик) — в зашифрованном теле
        info = {"run_name": run.name, "engagement": eng_label}
        header_base = {"run_id": run.id, "node_id": node_id, "node_name": node_name,
                       "modules": list(run.modules or []),
                       "rate_profile": run.rate_profile}
        node_obj = node
        s.expunge(node_obj)

    # claim_for_node расшифровывает учётки и переводит прогон в running за узлом
    wire = runs.claim_for_node(run_id, node_obj)
    if wire is None:
        with session_scope(sessions) as s:
            run = repo.get_scan_run(s, run_id)
            why = (run.error_message if run is not None and run.status == "failed"
                   else None) or "прогон уже забран или остановлен"
        raise OfflineError(why, code="run_not_pending")
    from scanner.nodes.codec import decode_job
    job = decode_job(wire)
    job_id = str(uuid.uuid4())
    expires = now + timedelta(days=valid_days)
    header = {"job_id": job_id, **header_base, "issued_at": now.isoformat(),
              "expires_at": expires.isoformat(), **_job_counts(job)}
    del job
    try:
        data = of.build(of.FORMAT_JOB, header, {"job": wire, "info": info},
                        signer=keys, recipient=recipient)
    except Exception as e:
        del wire
        with session_scope(sessions) as s:
            repo.set_scan_run_status(s, run_id, "failed",
                                     error_message=f"Не удалось сформировать задание для "
                                                   f"автономного узла: {e}"[:500])
        audit.record(subject=actor, action="offline_job_export", target=f"scan_run:{run_id}",
                     result="error", details={"error": f"{type(e).__name__}: {e}"[:500]})
        raise OfflineError(f"не удалось сформировать задание: {e}") from e
    del wire                                # учётки в открытом виде больше не нужны
    env = of.parse(data, of.FORMAT_JOB)
    try:
        with session_scope(sessions) as s:
            s.add(OfflineJobRow(id=job_id, run_id=run_id, node_id=node_id,
                                node_fingerprint=recipient.fingerprint,
                                status=STATUS_EXPORTED, job_sha256=env.sha256,
                                job_file=data.decode("utf-8"), exported_by=actor,
                                exported_at=now, expires_at=expires))
    except Exception as e:
        # прогон уже за узлом, а задания нет — иначе он висел бы в running вечно
        with session_scope(sessions) as s:
            repo.set_scan_run_status(s, run_id, "failed",
                                     error_message="Не удалось сохранить задание для "
                                                   "автономного узла — выгрузите заново "
                                                   "(«Повторить»)")
        audit.record(subject=actor, action="offline_job_export", target=f"scan_run:{run_id}",
                     result="error", details={"error": f"{type(e).__name__}: {e}"[:500]})
        raise
    audit.record(subject=actor, action="offline_job_export", target=f"scan_run:{run_id}",
                 result="ok", details={"job_id": job_id, "node_id": node_id,
                                       "node": node_name, "job_sha256": env.sha256,
                                       "expires_at": expires.isoformat(),
                                       **{k: header[k] for k in ("targets", "credentials")}})
    ev.safe_add(sessions, run_id, [ev.Event(
        "offline_export", ev.SUBJECT_RUN,
        f"задание выгружено для автономного узла «{node_name}», "
        f"действует до {expires:%d.%m.%Y}")])
    return ExportedJob(job_id, job_filename(node_name, run_id, now), data, expires)


def job_file(session: Session, run_id: int) -> tuple[str, bytes]:
    """Повторно скачать выгруженное задание (тот же файл, тот же id)."""
    row = session.scalar(select(OfflineJobRow).where(OfflineJobRow.run_id == run_id))
    if row is None:
        raise OfflineError("задание по прогону не выгружалось", code="not_found", status=404)
    if row.status != STATUS_EXPORTED or not row.job_file:
        raise OfflineError(f"задание {STATUS_LABELS.get(row.status, row.status).lower()} — "
                           "скачать его нельзя", code="job_closed")
    node = session.get(ScanNode, row.node_id) if row.node_id else None
    return (job_filename(node.name if node else "node", run_id, _aware(row.exported_at)),
            row.job_file.encode("utf-8"))


# ========== Приём результата ==========
def inspect_result(session: Session, data: bytes) -> dict:
    """Открытый заголовок файла результата (без проверки подписи) и что о нём
    знает центр: прогон, договор, статус задания — для предпросмотра."""
    try:
        h = dict(of.parse(data, of.FORMAT_RESULT).header)
    except of.OfflineFileError as e:
        raise OfflineError(str(e), code="bad_file", status=422) from e
    row = session.get(OfflineJobRow, str(h.get("job_id") or ""))
    run = repo.get_scan_run(session, row.run_id) if row is not None else None
    eng = session.get(Engagement, run.engagement_id) if run is not None else None
    h.update({"known_job": row is not None,
              "job_status": row.status if row is not None else None,
              "run_name": run.name if run is not None else None,
              "engagement": (eng.contract_ref or eng.name) if eng is not None else None})
    return h


def import_result(sessions: sessionmaker[Session], runs, audit, *, data: bytes,
                  actor: str, keys: KeyPair, now: datetime | None = None) -> dict:
    """Загрузить результат с носителя. Возвращает {run_id, status, job_id, …}."""
    now = now or _now()
    try:
        env = of.parse(data, of.FORMAT_RESULT)
    except of.OfflineFileError as e:
        raise OfflineError(str(e), code="bad_file", status=422) from e
    h = env.header
    job_id = str(h.get("job_id") or "")

    def _refuse(reason: str, message: str, *, code: str, status: int = 409,
                run_id: Any = None):
        audit.record(subject=actor, action="offline_result_import",
                     target=f"scan_run:{run_id or h.get('run_id')}", result="denied",
                     details={"reason": reason, "job_id": job_id or None,
                              "file_sha256": env.sha256, "node": h.get("node_name")})
        raise OfflineError(message, code=code, status=status)

    with session_scope(sessions) as s:
        row = s.get(OfflineJobRow, job_id) if job_id else None
        if row is None:
            _refuse("unknown_job", "задание из этого результата центр не выпускал "
                    "(или оно удалено вместе с прогоном)", code="unknown_job")
        run_id = row.run_id
        if row.status == STATUS_IMPORTED:
            same = row.result_sha256 == env.sha256
            _refuse("already_imported",
                    "этот результат уже загружен" if same else
                    "по заданию уже загружен другой результат", code="already_imported",
                    run_id=run_id)
        if row.status != STATUS_EXPORTED:
            _refuse(f"job_{row.status}", f"задание {STATUS_LABELS[row.status].lower()} — "
                    "результат не принимается", code=f"job_{row.status}", run_id=run_id)
        node = s.get(ScanNode, row.node_id) if row.node_id else None
        if node is None:
            _refuse("node_missing", "узел, для которого выпускалось задание, удалён",
                    code="node_missing", run_id=run_id)
        try:
            pub = node_public(node)
        except OfflineError as e:
            _refuse("node_key", str(e), code=e.code, run_id=run_id)
        if pub.fingerprint != row.node_fingerprint:
            _refuse("node_key_changed", "ключ узла сменился после выгрузки задания — "
                    "результат подписан прежним ключом", code="node_key_changed",
                    run_id=run_id)
        try:
            env.verify(pub)
        except of.OfflineFileError as e:
            _refuse("bad_signature", str(e), code="bad_signature", status=422,
                    run_id=run_id)
        if h.get("job_sha256") != row.job_sha256:
            _refuse("job_mismatch", "результат относится к другому файлу задания",
                    code="job_mismatch", run_id=run_id)
        run = repo.get_scan_run(s, run_id)
        if run is None or run.status not in {"running", "stopped"}:
            _refuse("run_state", f"прогон не ждёт результат (сейчас: "
                    f"{run.status if run else 'удалён'})", code="run_state", run_id=run_id)
        node_name, node_id = node.name, node.id
        contract = repo.load_allowlist_gate(s, run.engagement_id).networks
        scope = list(node.scope or [])

    try:
        body = env.open(keys)
    except of.OfflineFileError as e:
        _refuse("decrypt", str(e), code="bad_file", status=422, run_id=run_id)
    from scanner.nodes.codec import decode_outcome
    try:
        out_run_id, out = decode_outcome(body.get("outcome"))
    except Exception as e:  # noqa: BLE001 — тело от узла, ошибки разбора любые
        _refuse("bad_outcome", f"результат не разобран: {type(e).__name__}: {e}"[:300],
                code="bad_file", status=422, run_id=run_id)
    if out_run_id != run_id or h.get("run_id") != run_id:
        _refuse("run_mismatch", "результат относится к другому прогону",
                code="job_mismatch", run_id=run_id)
    # как у сетевого узла: данные по адресам вне allowlist договора ∩ сетей узла
    # отбрасываются — узел не может «дописать» в договор чужие хосты
    from scanner.api.routes_nodes import filter_outcome
    from scanner.nodes.jobs import node_gate
    _, nets = node_gate(contract, scope)
    dropped = filter_outcome(out, nets)
    if dropped:
        audit.record(subject=f"node:{node_name}", action="node_result_filtered",
                     target=f"scan_run:{run_id}", result="dropped",
                     details={"dropped": dropped, "node_id": node_id,
                              "offline_job": job_id})

    # журнал действий узла по заданию — в общий журнал аудита центра
    subject = f"node:{node_name}"
    for e in (body.get("audit") or [])[:5000]:
        if not isinstance(e, dict):
            continue
        details = e.get("details") if isinstance(e.get("details"), dict) else {}
        audit.record(subject=subject, action=str(e.get("action", ""))[:64],
                     target=str(e.get("target", ""))[:256],
                     result=str(e.get("result", ""))[:32],
                     details={**details, "node_ts": e.get("ts"), "offline_job": job_id})

    # прогон закрывается тем же путём, что и у сетевого узла
    with session_scope(sessions) as s:
        claimed = s.execute(update(OfflineJobRow).where(
            OfflineJobRow.id == job_id, OfflineJobRow.status == STATUS_EXPORTED).values(
            status=STATUS_IMPORTED, imported_at=now, imported_by=actor,
            result_sha256=env.sha256,
            result_summary={k: h.get(k) for k in ("hosts", "findings", "severity",
                                                  "targets", "denied", "errors",
                                                  "started_at", "finished_at")})
            .execution_options(synchronize_session=False))
        if claimed.rowcount != 1:
            raise OfflineError("результат уже загружается в другом окне",
                               code="already_imported")
    try:
        final = runs.persist_outcome(run_id, out)
    except Exception as e:
        # результат не сохранён — задание снова ждёт, файл можно загрузить ещё раз
        with session_scope(sessions) as s:
            s.execute(update(OfflineJobRow).where(OfflineJobRow.id == job_id).values(
                status=STATUS_EXPORTED, imported_at=None, imported_by=None,
                result_sha256=None, result_summary=None)
                .execution_options(synchronize_session=False))
        audit.record(subject=actor, action="offline_result_import",
                     target=f"scan_run:{run_id}", result="error",
                     details={"job_id": job_id, "error": f"{type(e).__name__}: {e}"[:500]})
        raise OfflineError(f"результат не сохранён: {type(e).__name__}; файл можно "
                           "загрузить повторно", code="persist_failed", status=500) from e
    audit.record(subject=actor, action="offline_result_import", target=f"scan_run:{run_id}",
                 result="ok", details={"job_id": job_id, "node_id": node_id,
                                       "node": node_name, "file_sha256": env.sha256,
                                       "status": final, "findings": len(out.findings),
                                       "hosts": h.get("hosts"),
                                       "dropped": dropped or None})
    ev.safe_add(sessions, run_id, [ev.Event(
        "offline_import", ev.SUBJECT_RUN,
        f"результат автономного узла «{node_name}» загружен с носителя")])
    return {"run_id": run_id, "status": final, "job_id": job_id, "node": node_name,
            "findings": len(out.findings), "hosts": h.get("hosts"),
            "dropped": dropped,
            "started_at": h.get("started_at"), "finished_at": h.get("finished_at")}


# ========== Отмена и просрочка ==========
def cancel_job(sessions: sessionmaker[Session], runs, audit, *, run_id: int,
               actor: str) -> None:
    with session_scope(sessions) as s:
        res = s.execute(update(OfflineJobRow).where(
            OfflineJobRow.run_id == run_id, OfflineJobRow.status == STATUS_EXPORTED)
            .values(status=STATUS_CANCELLED, job_file=None)
            .execution_options(synchronize_session=False))
        if res.rowcount != 1:
            raise OfflineError("нет задания, ожидающего результат", code="job_closed")
    runs.request_stop(run_id, actor=actor)
    audit.record(subject=actor, action="offline_job_cancel", target=f"scan_run:{run_id}",
                 result="ok")


def expire_jobs(sessions: sessionmaker[Session], audit, *,
                now: datetime | None = None) -> list[int]:
    """Задания без результата дольше срока + запаса: задание expired, прогон failed."""
    now = now or _now()
    expired: list[int] = []
    with session_scope(sessions) as s:
        rows = s.scalars(select(OfflineJobRow).where(
            OfflineJobRow.status == STATUS_EXPORTED,
            OfflineJobRow.expires_at < now - RESULT_GRACE)).all()
        for row in rows:
            res = s.execute(update(OfflineJobRow).where(
                OfflineJobRow.id == row.id, OfflineJobRow.status == STATUS_EXPORTED)
                .values(status=STATUS_EXPIRED, job_file=None)
                .execution_options(synchronize_session=False))
            if res.rowcount != 1:
                continue
            run = s.get(ScanRun, row.run_id)
            if run is not None and run.status in {"pending", "running"}:
                repo.set_scan_run_status(s, row.run_id, "failed", error_message=MSG_EXPIRED)
            expired.append(row.run_id)
    for run_id in expired:
        audit.record(subject="scanner", action="offline_job_expire",
                     target=f"scan_run:{run_id}", result="expired")
        ev.safe_add(sessions, run_id, [ev.run_finish("failed", message=MSG_EXPIRED)])
    return expired


def job_out(row: OfflineJobRow, node_name: str | None = None) -> dict:
    return {"job_id": row.id, "run_id": row.run_id, "node_id": row.node_id,
            "node_name": node_name, "status": row.status,
            "status_label": STATUS_LABELS.get(row.status, row.status),
            "node_fingerprint": row.node_fingerprint, "job_sha256": row.job_sha256,
            "exported_by": row.exported_by, "exported_at": row.exported_at,
            "expires_at": row.expires_at, "imported_by": row.imported_by,
            "imported_at": row.imported_at, "result_sha256": row.result_sha256,
            "result_summary": row.result_summary}
