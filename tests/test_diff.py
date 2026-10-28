"""Тесты сравнения прогонов (единственная полностью реализованная логика)."""
from scanner.core.models import Finding, FindingType
from scanner.reporting.diff import diff_runs


def _f(host: str, port: int, vuln: str) -> Finding:
    return Finding(module="vuln", host=host, finding_type=FindingType.VULN,
                   title=vuln, port=port, vuln_id=vuln)


def test_open_fixed_new_regression():
    prev = [_f("10.0.0.1", 443, "CVE-2024-1"), _f("10.0.0.1", 22, "CVE-2024-2")]
    # CVE-2024-3 помечено fixed в более раннем прогоне и теперь вернулось -> regression
    regressed = {_f("10.0.0.3", 3389, "CVE-2024-3").dedup_key()}
    cur = [
        _f("10.0.0.1", 443, "CVE-2024-1"),   # был и остался -> open
        _f("10.0.0.2", 80, "CVE-2024-4"),    # новый -> new
        _f("10.0.0.3", 3389, "CVE-2024-3"),  # вернулся -> regression
    ]
    # CVE-2024-2 исчез из cur -> fixed

    d = diff_runs(prev, cur, historically_fixed=regressed)

    assert {f.vuln_id for f in d.open} == {"CVE-2024-1"}
    assert {f.vuln_id for f in d.new} == {"CVE-2024-4"}
    assert {f.vuln_id for f in d.regression} == {"CVE-2024-3"}
    assert {f.vuln_id for f in d.fixed} == {"CVE-2024-2"}


def test_dedup_key_stable():
    assert _f("10.0.0.1", 443, "CVE-1").dedup_key() == _f("10.0.0.1", 443, "CVE-1").dedup_key()
    assert _f("10.0.0.1", 443, "CVE-1").dedup_key() != _f("10.0.0.1", 22, "CVE-1").dedup_key()
