"""Автономный узел: установка, проверки задания, выпуск результата."""
from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from scanner.nodes import offline_files as of
from scanner.nodes import offline_node as on
from scanner.nodes.offline_crypto import ROLE_CENTER, ROLE_NODE, KeyPair, parse_public

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


@dataclass
class FakeFinding:
    host: str
    severity: str = "high"


@dataclass
class FakeOutcome:
    findings: list = field(default_factory=list)
    services: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    allowed: list = field(default_factory=list)
    denied: list = field(default_factory=list)
    errors: dict = field(default_factory=dict)
    stopped: bool = False


@pytest.fixture
def center():
    return KeyPair.derive(ROLE_CENTER, "center-secret-1234567890", purpose="scanner-center")


@pytest.fixture
def node(tmp_path, center):
    on.init_node(tmp_path / "node", name="АСУ-ТП-1", scope=["10.10.0.0/24", "10.10.1.5"],
                 center_key=center.public.export())
    return on.OfflineNode.load(tmp_path / "node")


def make_job(center, node, *, job_id="job-1", expires=NOW + timedelta(days=14), body=None):
    header = {"job_id": job_id, "run_id": 42, "run_name": "АСУ ТП", "node_id": 3,
              "node_name": node.name, "issued_at": NOW.isoformat(),
              "expires_at": expires.isoformat(), "modules": ["discovery", "vuln"]}
    return of.build(of.FORMAT_JOB, header,
                    body or {"job": {"targets": ["10.10.0.0/24"], "secret": "x"}},
                    signer=center, recipient=node.public)


def test_init_creates_private_files(tmp_path, center, node):
    home = tmp_path / "node"
    assert stat.S_IMODE((home / on.KEYS_FILE).stat().st_mode) == 0o600
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    pub = parse_public((home / on.NODE_PUB_FILE).read_text(), ROLE_NODE)
    assert pub == node.public
    assert node.scope == ["10.10.0.0/24", "10.10.1.5/32"]
    assert node.center == center.public
    with pytest.raises(on.OfflineNodeError, match="уже установлен"):
        on.init_node(home, name="x", scope=["10.0.0.0/8"], center_key=center.public.export())


def test_init_validates(tmp_path, center):
    with pytest.raises(on.OfflineNodeError, match="сети"):
        on.init_node(tmp_path / "a", name="n", scope=[], center_key=center.public.export())
    with pytest.raises(on.OfflineNodeError, match="не сеть"):
        on.init_node(tmp_path / "a", name="n", scope=["evil.example"],
                     center_key=center.public.export())
    node_key = KeyPair.generate(ROLE_NODE).public.export()
    with pytest.raises(on.OfflineNodeError, match="ключ центра"):
        on.init_node(tmp_path / "a", name="n", scope=["10.0.0.0/8"], center_key=node_key)


def _run(node, data, **kw):
    seen = {}

    def execute(job, registry, *, audit, local_allowlist, **_):
        seen["job"], seen["gate"] = job, local_allowlist
        audit.record(subject="scanner", action="module_start", target="discovery",
                     result="ok")
        return FakeOutcome(findings=[FakeFinding("10.10.0.7"), FakeFinding("10.10.0.7", "low")],
                           allowed=["10.10.0.7", "10.10.0.8"])

    out = on.run_job(node, data, registry={}, execute=execute,
                     decode_job=lambda d: d, encode_outcome=lambda o: {"n": len(o.findings)},
                     now=lambda: NOW, version="test", **kw)
    return out, seen


def test_run_job_produces_signed_result_for_center(center, node):
    job = make_job(center, node)
    data, _header = _run(node, job)[0]
    res = of.parse(data, of.FORMAT_RESULT)
    res.verify(node.public)
    assert res.header["job_id"] == "job-1" and res.header["run_id"] == 42
    assert res.header["job_sha256"] == of.parse(job, of.FORMAT_JOB).sha256
    assert res.header["findings"] == 2 and res.header["severity"] == {"high": 1, "low": 1}
    body = res.open(center)
    assert body["outcome"] == {"n": 2}
    actions = [e["action"] for e in body["audit"]]
    assert actions == ["offline_job_start", "module_start", "offline_job_finish"]
    assert body["node"]["scope"] == node.scope
    # узлу самому результат не прочитать: он зашифрован на ключ центра
    with pytest.raises(of.OfflineFileError):
        res.open(node.keys)


def test_local_allowlist_passed_to_executor(center, node):
    (_, _), seen = _run(node, make_job(center, node))
    assert seen["gate"] == ["10.10.0.0/24", "10.10.1.5/32"]
    assert seen["job"]["secret"] == "x"


def test_job_from_other_center_rejected(node):
    evil = KeyPair.derive(ROLE_CENTER, "other-center-secret-123", purpose="scanner-center")
    with pytest.raises(on.OfflineNodeError, match="не от того центра"):
        _run(node, make_job(evil, node))


def test_job_for_other_node_rejected(tmp_path, center, node):
    on.init_node(tmp_path / "other", name="Другой", scope=["10.20.0.0/24"],
                 center_key=center.public.export())
    other = on.OfflineNode.load(tmp_path / "other")
    with pytest.raises(on.OfflineNodeError, match="для другого узла"):
        _run(node, make_job(center, other))


def test_expired_job_rejected(center, node):
    with pytest.raises(on.OfflineNodeError, match="срок действия"):
        _run(node, make_job(center, node, expires=NOW - timedelta(minutes=1)))


def test_job_runs_only_once(center, node):
    data = make_job(center, node)
    (_, header), _ = _run(node, data)
    on.record_done(node, header, "result.scnres")
    with pytest.raises(on.OfflineNodeError, match="уже выполнялось"):
        _run(node, data)
    # другое задание — можно
    _run(node, make_job(center, node, job_id="job-2"))
    assert [e["job_id"] for e in node.journal()] == ["job-1"]


def test_result_filename(center, node):
    (_, header), _ = _run(node, make_job(center, node))
    name = on.result_filename(header)
    assert name.startswith("result-") and name.endswith(".scnres") and "run42" in name


def test_load_missing_home(tmp_path):
    with pytest.raises(on.OfflineNodeError, match="не установлен"):
        on.OfflineNode.load(tmp_path / "nope")


def test_audit_inner_sink_receives_entries(center, node):
    got = []

    class Sink:
        def record(self, **kw):
            got.append(kw["action"])

    _run(node, make_job(center, node), audit=Sink())
    assert got[0] == "offline_job_start" and got[-1] == "offline_job_finish"
    assert json.dumps(got)
