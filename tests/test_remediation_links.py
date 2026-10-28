"""Ссылки на устранение: отбор, подписи, порядок и вывод в отчётах."""
import io
import zipfile

from scanner.core.models import Finding, FindingType, Severity
from scanner.reporting.model import build_report
from scanner.reporting.remediation import (
    RefKind,
    RemediationResolver,
    curate_refs,
    describe_ref,
)
from scanner.reporting.render import ReportFormat, ReportRenderer
from tests import reporting_fixtures as fx


def test_describe_ref_labels_and_drops_noise():
    assert describe_ref("https://msrc.microsoft.com/update-guide/vulnerability/CVE-1").label \
        == "Бюллетень Microsoft"
    assert describe_ref("https://wiki.astralinux.ru/x").kind is RefKind.OS
    assert describe_ref("https://redos.red-soft.ru/search/?q=CVE-1").label == "Бюллетень РЕД ОС"
    assert describe_ref("https://bdu.fstec.ru/vul/2023-04110").label == "БДУ ФСТЭК 2023-04110"
    assert describe_ref("https://cwe.mitre.org/data/definitions/22.html").label == "CWE-22"
    assert describe_ref("https://git.kernel.org/stable/c/abc").kind is RefKind.PATCH
    assert describe_ref("https://github.com/o/r/security/advisories/GHSA-x").kind \
        is RefKind.VENDOR
    assert describe_ref("https://github.com/o/r/commit/abc").kind is RefKind.PATCH
    for noise in ("https://www.exploit-db.com/exploits/1", "https://vuldb.com/?id.1",
                  "https://github.com/someone/poc", "https://lists.debian.org/x",
                  "https://bugzilla.redhat.com/1", "https://twitter.com/x",
                  "https://www.securitylab.ru/news/1.php", "ftp://example.org/x", "мусор"):
        assert describe_ref(noise) is None, noise


def test_curate_refs_orders_dedups_and_limits():
    urls = [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-1",
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://security-tracker.debian.org/tracker/CVE-2023-1",
        "https://www.exploit-db.com/exploits/1",
        "https://vendor.example/advisory/1",
        "http://vendor.example/advisory/1/",          # дубль
        "https://github.com/o/r/commit/abc",
    ]
    assert curate_refs(urls) == [
        "https://vendor.example/advisory/1",
        "https://github.com/o/r/commit/abc",
        "https://security-tracker.debian.org/tracker/CVE-2023-1",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-1",
        "https://cwe.mitre.org/data/definitions/79.html",
    ]
    many = [f"https://vendor{i}.example/a" for i in range(30)]
    assert len(curate_refs(many)) == 10


def test_every_finding_gets_remediation_links():
    r = fx.resolver()
    for f in fx.current_run() + fx.previous_run():
        refs = r.resolve(f).references
        assert refs, f.title
        assert all(describe_ref(u) for u in refs)


def test_links_from_bdu_record_nvd_and_topics():
    r = fx.resolver()
    by_title = {f.title: r.resolve(f).references for f in fx.current_run()}
    ssh = by_title["OpenSSH: удалённое выполнение кода через ssh-agent"]
    assert ssh[0] == "https://www.openssh.com/txt/release-9.3p2"     # производитель первым
    assert "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1018SE17" in ssh
    assert "https://cwe.mitre.org/data/definitions/428.html" in ssh
    assert not any("exploit-db" in u for u in ssh)
    rdp = by_title["RDP: BlueKeep"]
    assert rdp[0].startswith("https://portal.msrc.microsoft.com/")
    assert not any("packetstorm" in u for u in rdp)
    assert by_title["Не задан максимальный срок пароля"][0] == \
        "https://cisofy.com/lynis/controls/AUTH-9286/"
    assert "https://cwe.mitre.org/data/definitions/1392.html" in \
        by_title["Стандартный пароль admin/admin на SSH"]
    assert by_title["Открыт Telnet"] == ["https://cwe.mitre.org/data/definitions/319.html"]


def test_benchmark_refs_are_used():
    f = Finding(module="config_audit", host="h", finding_type=FindingType.CONFIG,
                title="Правило", severity=Severity.LOW, vuln_id="rule-1")
    r = RemediationResolver(benchmark_refs={"rule-1": ["https://benchmarks.example/rule-1"]})
    assert r.resolve(f).references == ["https://benchmarks.example/rule-1"]


def test_reports_show_labelled_links():
    report = build_report(fx.current_run(), previous=fx.previous_run(),
                          resolver=fx.resolver())
    html = ReportRenderer().render_html(report)
    assert html.count("Ссылки на устранение") == report.summary.total
    assert "Бюллетень OpenSSH" in html and "Бюллетень Astra Linux" in html
    assert 'href="https://www.openssh.com/txt/release-9.3p2"' in html
    raw = ReportRenderer().render(report, ReportFormat.DOCX)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        rels = z.read("word/_rels/document.xml.rels").decode()
        xml = z.read("word/document.xml").decode()
    assert 'Target="https://www.openssh.com/txt/release-9.3p2"' in rels
    assert "w:hyperlink" in xml and "Ссылки на устранение" in xml
