"""А2: записи БДУ для отчёта — одним запросом на пачку, а не по запросу на id."""
from __future__ import annotations

import pytest
from sqlalchemy import event

from scanner.api.main import bdu_resolver_factory
from scanner.core.models import Finding, FindingType, Severity
from scanner.feeds.bdu_fstec import BduRecord
from scanner.feeds.store import (
    CachingReferenceStore,
    InMemoryReferenceStore,
    SqlReferenceStore,
    UnavailableReferenceStore,
    get_bdu_many,
)

RECS = [BduRecord(bdu_id=f"BDU:2024-{i:05d}", title=f"Уязвимость {i}",
                  remediation=f"Обновить пакет {i}") for i in range(1, 1201)]


def _sql():
    s = SqlReferenceStore.from_url("sqlite://", create=True)
    s.upsert_bdu(RECS)
    return s


def _mem():
    s = InMemoryReferenceStore()
    s.upsert_bdu(RECS)
    return s


@pytest.fixture(params=["memory", "sqlite"])
def store(request):
    return _mem() if request.param == "memory" else _sql()


def _finding(i: int, **kw) -> Finding:
    return Finding(module="vuln", host="10.0.0.1", finding_type=FindingType.VULN,
                   title=f"f{i}", severity=Severity.HIGH, **kw)


def test_get_bdu_many_case_and_missing(store):
    got = store.get_bdu_many(["bdu:2024-00001", "BDU:2024-00002", "BDU:1999-00000"])
    assert sorted(got) == ["BDU:2024-00001", "BDU:2024-00002"]
    assert got["BDU:2024-00001"].title == "Уязвимость 1"
    assert store.get_bdu_many([]) == {}


def test_sql_batch_is_chunked_not_per_id():
    s = _sql()
    selects: list[str] = []
    event.listen(s.engine, "before_cursor_execute",
                 lambda *a: selects.append(a[2]) if a[2].lstrip().upper().startswith("SELECT") else None)
    got = s.get_bdu_many(r.bdu_id for r in RECS)
    assert len(got) == 1200
    # 1200 id → 3 пачки по ≤500 (лимит параметров SQLite), а не 1200 запросов
    assert len(selects) == 3


def test_resolver_factory_uses_one_batch():
    s = _sql()
    calls: list[int] = []
    orig = s.get_bdu_many
    s.get_bdu_many = lambda ids: calls.append(len(set(ids))) or orig(ids)
    s.get_bdu = lambda _id: pytest.fail("per-id lookup must not be used")
    findings = [_finding(i, bdu_ids=[f"bdu:2024-{i:05d}"]) for i in range(1, 51)]
    findings.append(_finding(99, vuln_id="BDU:2024-00100"))
    resolver = bdu_resolver_factory(s)(findings)
    assert calls == [51]
    assert len(resolver.bdu) == 51 and "BDU:2024-00100" in resolver.bdu


def test_resolver_factory_store_unavailable():
    resolver = bdu_resolver_factory(UnavailableReferenceStore("нет БД"))(
        [_finding(1, bdu_ids=["BDU:2024-00001"])])
    assert resolver.bdu == {}


def test_fallback_for_store_without_batch():
    class OnlyGet:          # как справочник центра на узле сканирования
        def __init__(self):
            self.inner = _mem()
            self.n = 0

        def get_bdu(self, bid):
            self.n += 1
            return self.inner.get_bdu(bid)

    st = OnlyGet()
    got = get_bdu_many(st, ["bdu:2024-00003", "BDU:2024-00003", "BDU:1999-00000"])
    assert list(got) == ["BDU:2024-00003"] and st.n == 2


def test_caching_store_batches_only_missing():
    inner = _mem()
    asked: list[list[str]] = []
    orig = inner.get_bdu_many
    inner.get_bdu_many = lambda ids: asked.append(sorted(ids)) or orig(ids)
    c = CachingReferenceStore(inner)
    assert c.get_bdu("BDU:2024-00001") is not None
    got = c.get_bdu_many(["BDU:2024-00001", "BDU:2024-00002", "BDU:1999-00000"])
    assert sorted(got) == ["BDU:2024-00001", "BDU:2024-00002"]
    assert asked == [["BDU:1999-00000", "BDU:2024-00002"]]
    c.get_bdu_many(["BDU:2024-00002", "BDU:1999-00000"])
    assert len(asked) == 1
