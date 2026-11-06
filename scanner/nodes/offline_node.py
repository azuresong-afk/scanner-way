"""Автономный узел-сканер: установка, приём задания с носителя, выпуск результата.

Узел в закрытом сегменте (АСУ ТП, закрытый контур) не имеет никакой сетевой
связи с центром. Обмен — двумя файлами на носителе:

    центр  --«Выгрузить задание»-->  job.scnjob  --носитель-->  узел
    узел   --scanner node run-job-->  result.scnres  --носитель-->  центр
    центр  --«Загрузить результат»-->  отчёты, «Активы», «Что исправить»

Каталог узла (SCANNER_NODE_HOME, по умолчанию /var/lib/scanner-node):

    node.json        имя узла и его собственный allowlist (сети сегмента)
    node-keys.json   закрытые ключи узла (права 0600, с узла не выносится)
    node.pub         открытый ключ узла — переносится в центр при регистрации
    center.pub       открытый ключ центра, закреплённый при установке
    journal.jsonl    журнал выполненных заданий (защита от повторного запуска)

Что проверяет узел перед запуском задания:
1. подпись центра — по закреплённому center.pub (чужое или изменённое задание
   отклоняется до расшифровки);
2. задание выпущено именно для этого узла (отпечаток получателя);
3. срок действия задания не истёк (по часам узла);
4. задание с этим id ещё не выполнялось на узле (журнал);
5. цели задания пересекаются с локальным allowlist узла: даже подписанное
   задание не заставит узел сканировать сети вне node.json.
"""
from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.nodes import offline_files as of
from scanner.nodes.offline_crypto import (
    ROLE_CENTER,
    ROLE_NODE,
    KeyPair,
    OfflineCryptoError,
    PublicKeys,
    parse_public,
)

DEFAULT_HOME = "/var/lib/scanner-node"
NODE_FILE = "node.json"
KEYS_FILE = "node-keys.json"
NODE_PUB_FILE = "node.pub"
CENTER_PUB_FILE = "center.pub"
JOURNAL_FILE = "journal.jsonl"
MAX_AUDIT_ENTRIES = 5000


class OfflineNodeError(Exception):
    """Ошибка, о которой узел сообщает оператору без трейсбека."""


def default_home() -> Path:
    return Path(os.environ.get("SCANNER_NODE_HOME") or DEFAULT_HOME)


def parse_scope(items: Iterable[str]) -> list[str]:
    """Сети узла: IP или CIDR. Пусто — ошибка: узел без allowlist не сканирует."""
    import ipaddress
    out: list[str] = []
    for raw in items:
        for part in str(raw).replace(",", " ").split():
            try:
                out.append(str(ipaddress.ip_network(part, strict=False)))
            except ValueError as e:
                raise OfflineNodeError(f"не сеть и не IP-адрес: {part}") from e
    if not out:
        raise OfflineNodeError("укажите сети сегмента узла (--scope 10.10.0.0/16 …)")
    return list(dict.fromkeys(out))


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_ts(value: Any) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


# ========== Установка узла ==========
def init_node(home: Path, *, name: str, scope: Iterable[str], center_key: str,
              force: bool = False) -> PublicKeys:
    """Создать узел: ключи, allowlist, закреплённый ключ центра. Возвращает
    открытый ключ узла (его переносят в центр)."""
    name = (name or "").strip()
    if not name or len(name) > 128:
        raise OfflineNodeError("укажите имя узла (до 128 символов), как в центре")
    nets = parse_scope(scope)
    try:
        center = parse_public(center_key, ROLE_CENTER)
    except OfflineCryptoError as e:
        raise OfflineNodeError(f"ключ центра: {e}") from e
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    if (home / KEYS_FILE).exists() and not force:
        raise OfflineNodeError(f"узел уже установлен в {home}; для новой пары ключей "
                               "добавьте --force (старые задания станут недействительны, "
                               "ключ узла в центре придётся заменить)")
    keys = KeyPair.generate(ROLE_NODE)
    _write_private(home / KEYS_FILE, json.dumps(keys.to_json()))
    pub = keys.public
    (home / NODE_PUB_FILE).write_text(
        f"# Открытый ключ автономного узла «{name}». Отпечаток: {pub.fingerprint}\n"
        f"{pub.export()}\n", encoding="utf-8")
    (home / CENTER_PUB_FILE).write_text(center.export() + "\n", encoding="utf-8")
    (home / NODE_FILE).write_text(json.dumps(
        {"name": name, "scope": nets, "center_fingerprint": center.fingerprint,
         "created_at": _now().isoformat()}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return pub


@dataclass(slots=True)
class OfflineNode:
    home: Path
    name: str
    scope: list[str]
    keys: KeyPair = field(repr=False)
    center: PublicKeys

    @classmethod
    def load(cls, home: Path) -> OfflineNode:
        if not (home / KEYS_FILE).exists():
            raise OfflineNodeError(f"узел не установлен в {home}: выполните "
                                   "scanner node init")
        try:
            meta = json.loads((home / NODE_FILE).read_text(encoding="utf-8"))
            keys = KeyPair.from_json(json.loads((home / KEYS_FILE).read_text("utf-8")))
            center = parse_public((home / CENTER_PUB_FILE).read_text("utf-8"), ROLE_CENTER)
        except (OSError, ValueError, OfflineCryptoError) as e:
            raise OfflineNodeError(f"каталог узла {home} повреждён: {e}") from e
        if keys.role != ROLE_NODE:
            raise OfflineNodeError("в каталоге узла лежат не ключи узла")
        return cls(home, str(meta.get("name") or ""), parse_scope(meta.get("scope") or []),
                   keys, center)

    @property
    def public(self) -> PublicKeys:
        return self.keys.public

    # --- журнал выполненных заданий ---
    def journal(self) -> list[dict]:
        path = self.home / JOURNAL_FILE
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def _journal_add(self, entry: dict) -> None:
        with open(self.home / JOURNAL_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # --- задание ---
    def check_job(self, data: bytes, *, now: datetime | None = None) -> of.Envelope:
        """Проверки 1–4 (подпись, получатель, срок, повтор). Тело не трогает."""
        env = of.parse(data, of.FORMAT_JOB)
        try:
            env.verify(self.center)
        except of.OfflineFileError as e:
            raise OfflineNodeError(f"{e}. Задание не от того центра, чей ключ "
                                   f"закреплён на узле ({self.center.fingerprint})") from e
        h = env.header
        if h.get("recipient") != self.public.fingerprint:
            raise OfflineNodeError(
                f"задание выпущено для другого узла «{h.get('node_name')}» "
                f"({h.get('recipient')}); этот узел — «{self.name}» "
                f"({self.public.fingerprint})")
        expires = _parse_ts(h.get("expires_at"))
        if expires is None:
            raise OfflineNodeError("в задании нет срока действия")
        if (now or _now()) > expires:
            raise OfflineNodeError(f"срок действия задания истёк {expires:%d.%m.%Y %H:%M} UTC; "
                                   "выгрузите задание из центра заново. Если срок не "
                                   "должен был истечь — проверьте часы узла")
        job_id = str(h.get("job_id") or "")
        if not job_id:
            raise OfflineNodeError("в задании нет идентификатора")
        done = [e for e in self.journal() if e.get("job_id") == job_id]
        if done:
            raise OfflineNodeError(f"задание {job_id} уже выполнялось на узле "
                                   f"{done[-1].get('finished_at', '')[:16]}; результат — "
                                   f"{done[-1].get('result_file') or 'см. журнал'}")
        return env


class CollectingAudit:
    """Аудит узла: в локальную БД (если задана) и копия в файл результата,
    чтобы в журнале центра было видно, что именно узел делал по заданию."""

    def __init__(self, inner=None):
        self.inner = inner
        self.entries: list[dict] = []
        self.dropped = 0

    def record(self, *, subject: str, action: str, target: str, result: str,
               details=None) -> None:
        if self.inner is not None:
            self.inner.record(subject=subject, action=action, target=target,
                              result=result, details=details)
        if len(self.entries) >= MAX_AUDIT_ENTRIES:
            self.dropped += 1
            return
        from scanner.core.audit import normalize_details
        self.entries.append({"ts": _now().isoformat(), "subject": subject,
                             "action": action, "target": target, "result": result,
                             "details": normalize_details(details)})


Executor = Callable[..., Any]


def _default_execute(job, registry, **kw):
    from scanner.nodes.agent import execute_job
    return execute_job(job, registry, **kw)


def _default_decode_job(data):
    from scanner.nodes.codec import decode_job
    return decode_job(data)


def _default_encode_outcome(out):
    from scanner.nodes.codec import encode_outcome
    return encode_outcome(out)


def _outcome_counts(out: Any) -> dict[str, Any]:
    findings = list(getattr(out, "findings", []) or [])
    sev: dict[str, int] = {}
    for f in findings:
        k = str(getattr(f, "severity", "info"))
        sev[k] = sev.get(k, 0) + 1
    hosts = {getattr(s, "host", None) for s in getattr(out, "services", []) or []}
    hosts |= {getattr(h, "host", None) for h in getattr(out, "hosts", []) or []}
    hosts.discard(None)
    return {"hosts": len(hosts), "findings": len(findings), "severity": sev,
            "targets": len(getattr(out, "allowed", []) or []),
            "denied": len(getattr(out, "denied", []) or []),
            "errors": sorted((getattr(out, "errors", {}) or {}).keys()),
            "stopped": bool(getattr(out, "stopped", False))}


def run_job(node: OfflineNode, data: bytes, *, registry, audit=None,
            progress: Callable[[dict], None] | None = None,
            events: Callable[[Any], None] | None = None,
            should_stop: Callable[[], bool] | None = None,
            execute: Executor | None = None,
            decode_job: Callable[[Any], Any] | None = None,
            encode_outcome: Callable[[Any], Any] | None = None,
            version: str = "",
            reference: dict | None = None,
            now: Callable[[], datetime] = _now) -> tuple[bytes, dict]:
    """Проверить и выполнить задание, вернуть (файл результата, заголовок).

    reference — сведения о справочниках узла (сколько записей, на какую дату):
    центр показывает их рядом с результатом, по ним видно, насколько свежими
    данными узел сопоставлял находки с БДУ/CVE.
    execute/decode_job/encode_outcome — исполнение и кодек ядра узлов
    (scanner.nodes.agent / scanner.nodes.codec); параметры — для тестов."""
    env = node.check_job(data, now=now())
    try:
        body = env.open(node.keys)
    except of.OfflineFileError as e:
        raise OfflineNodeError(str(e)) from e
    h = env.header
    job_id = str(h["job_id"])
    sink = CollectingAudit(audit)
    actor = f"node:{node.name}"
    sink.record(subject=actor, action="offline_job_start", target=f"job:{job_id}",
                result="ok", details={"run_id": h.get("run_id"),
                                      "job_sha256": env.sha256,
                                      "modules": h.get("modules")})
    job = (decode_job or _default_decode_job)(body.get("job"))
    started = now()
    out = (execute or _default_execute)(
        job, registry, audit=sink, local_allowlist=list(node.scope),
        progress=progress, should_stop=should_stop, events=events)
    finished = now()
    del job, body                       # учётки больше не нужны
    counts = _outcome_counts(out)
    sink.record(subject=actor, action="offline_job_finish", target=f"job:{job_id}",
                result="stopped" if counts["stopped"] else "ok",
                details={k: counts[k] for k in ("targets", "denied", "findings", "errors")})
    header = {"job_id": job_id, "run_id": h.get("run_id"), "run_name": h.get("run_name"),
              "engagement": h.get("engagement"), "node_id": h.get("node_id"),
              "node_name": node.name, "job_sha256": env.sha256,
              "started_at": started.isoformat(), "finished_at": finished.isoformat(),
              "reference_as_of": (reference or {}).get("as_of"), **counts}
    result_body = {
        "outcome": (encode_outcome or _default_encode_outcome)(out),
        "node": {"name": node.name, "hostname": socket.gethostname(),
                 "version": version, "scope": node.scope, "reference": reference or {}},
        "audit": sink.entries, "audit_dropped": sink.dropped,
    }
    try:
        data_out = of.build(of.FORMAT_RESULT, header, result_body, signer=node.keys,
                            recipient=node.center)
    except of.OfflineFileError as e:
        raise OfflineNodeError(str(e)) from e
    return data_out, {**header, "signer": node.public.fingerprint,
                      "recipient": node.center.fingerprint}


def record_done(node: OfflineNode, header: dict, result_file: str) -> None:
    node._journal_add({"job_id": header.get("job_id"), "run_id": header.get("run_id"),
                       "job_sha256": header.get("job_sha256"),
                       "started_at": header.get("started_at"),
                       "finished_at": header.get("finished_at"),
                       "findings": header.get("findings"), "result_file": result_file})


def result_filename(header: dict) -> str:
    ts = (_parse_ts(header.get("finished_at")) or _now()).strftime("%Y%m%d-%H%M")
    safe = "".join(c if c.isalnum() or c in "-_" else "_"
                   for c in str(header.get("node_name") or "node"))[:40]
    return f"result-{safe}-run{header.get('run_id')}-{ts}{of.FILE_SUFFIX[of.FORMAT_RESULT]}"
