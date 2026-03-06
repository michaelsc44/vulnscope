from io import StringIO

from rich.console import Console

from vulnscope.models import InstalledPackage, ScanResult, Severity, Vulnerability
from vulnscope.ui.tables import print_summary


def _make_pkg(name="libfoo", version="1.0", ecosystem="deb"):
    return InstalledPackage(
        name=name, version=version, ecosystem=ecosystem,
        source="dpkg", arch="amd64", purl=f"pkg:{ecosystem}/{name}@{version}",
    )


def _make_vuln(
    cve_id="CVE-2024-0001",
    pkg_name="libfoo",
    severity=Severity.HIGH,
    fixed_version=None,
    is_kev=False,
    kev_due_date=None,
    ecosystem="deb",
):
    return Vulnerability(
        cve_id=cve_id,
        aliases=[],
        title="Test vuln",
        description="desc",
        severity=severity,
        cvss_score=7.5,
        cvss_vector=None,
        cwe_ids=[],
        affected_package=_make_pkg(name=pkg_name, ecosystem=ecosystem),
        fixed_version=fixed_version,
        is_known_exploited=is_kev,
        kev_due_date=kev_due_date,
        references=[],
        published_date=None,
        source="osv",
    )


def _make_result(vulns=None):
    return ScanResult(
        scan_id="test-001",
        timestamp="2024-01-01T00:00:00Z",
        os_info={"pretty_name": "Ubuntu 22.04", "kernel_version": "5.15.0"},
        total_packages=100,
        vulnerabilities=vulns or [],
        scan_duration_seconds=2.5,
    )


def _capture_summary(result):
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    print_summary(result, console=console)
    return buf.getvalue()


class TestPrintSummaryNoVulns:
    def test_no_vulns_shows_clean(self):
        output = _capture_summary(_make_result())
        assert "No vulnerabilities found" in output

    def test_no_vulns_shows_header(self):
        output = _capture_summary(_make_result())
        assert "VulnScope Summary" in output
        assert "100 packages" in output


class TestPrintSummaryRiskBreakdown:
    def test_severity_counts(self):
        vulns = [
            _make_vuln("CVE-2024-0001", severity=Severity.CRITICAL),
            _make_vuln("CVE-2024-0002", severity=Severity.HIGH),
            _make_vuln("CVE-2024-0003", severity=Severity.HIGH),
            _make_vuln("CVE-2024-0004", severity=Severity.LOW),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "LOW" in output
        assert "Risk Score" in output

    def test_total_count(self):
        vulns = [
            _make_vuln("CVE-2024-0001"),
            _make_vuln("CVE-2024-0002"),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "TOTAL" in output


class TestPrintSummaryTopPackages:
    def test_top_packages_listed(self):
        vulns = [
            _make_vuln("CVE-2024-0001", pkg_name="openssl"),
            _make_vuln("CVE-2024-0002", pkg_name="openssl"),
            _make_vuln("CVE-2024-0003", pkg_name="openssl"),
            _make_vuln("CVE-2024-0004", pkg_name="curl"),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "openssl" in output
        assert "curl" in output
        assert "Top 5" in output

    def test_limits_to_five(self):
        pkgs = [f"pkg{i}" for i in range(8)]
        vulns = [_make_vuln(f"CVE-2024-{i:04d}", pkg_name=p) for i, p in enumerate(pkgs)]
        output = _capture_summary(_make_result(vulns))
        # Should show top 5, all have same count so order is stable from sort
        lines_with_pkg = [line for line in output.splitlines() if any(f"pkg{i}" in line for i in range(8))]
        assert len(lines_with_pkg) == 5


class TestPrintSummaryKEV:
    def test_kev_section_shown(self):
        vulns = [
            _make_vuln("CVE-2024-0001", is_kev=True, kev_due_date="2024-02-01"),
            _make_vuln("CVE-2024-0002", is_kev=False),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "Known Exploited" in output
        assert "CVE-2024-0001" in output
        assert "2024-02-01" in output

    def test_no_kev_section_when_none(self):
        vulns = [_make_vuln("CVE-2024-0001", is_kev=False)]
        output = _capture_summary(_make_result(vulns))
        assert "Known Exploited" not in output


class TestPrintSummaryActionable:
    def test_fixable_packages_shown(self):
        vulns = [
            _make_vuln("CVE-2024-0001", pkg_name="openssl", fixed_version="3.0.3", ecosystem="deb"),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "Actionable" in output
        assert "openssl" in output
        assert "3.0.3" in output
        assert "apt install" in output

    def test_pip_update_command(self):
        vulns = [
            _make_vuln("CVE-2024-0001", pkg_name="requests", fixed_version="2.32.0", ecosystem="pypi"),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "pip install requests>=2.32.0" in output

    def test_npm_update_command(self):
        vulns = [
            _make_vuln("CVE-2024-0001", pkg_name="express", fixed_version="4.19.0", ecosystem="npm"),
        ]
        output = _capture_summary(_make_result(vulns))
        assert "npm install express@4.19.0" in output

    def test_no_fixes_message(self):
        vulns = [_make_vuln("CVE-2024-0001", fixed_version=None)]
        output = _capture_summary(_make_result(vulns))
        assert "No fixes currently available" in output

    def test_deduplicates_packages(self):
        vulns = [
            _make_vuln("CVE-2024-0001", pkg_name="openssl", fixed_version="3.0.3", ecosystem="deb"),
            _make_vuln("CVE-2024-0002", pkg_name="openssl", fixed_version="3.0.3", ecosystem="deb"),
        ]
        output = _capture_summary(_make_result(vulns))
        # Should show "1 packages can be updated to fix 2 vulnerabilities"
        assert "1 packages can be updated" in output
        assert "2 vulnerabilities" in output


class TestPrintSummaryCLI:
    def test_summary_only_flag_exists(self):
        from click.testing import CliRunner

        from vulnscope.cli import scan
        runner = CliRunner()
        result = runner.invoke(scan, ["--help"])
        assert "--summary-only" in result.output
