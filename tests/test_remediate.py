"""Tests for vulnscope.remediate module."""

from types import SimpleNamespace

from vulnscope.models import InstalledPackage, ScanResult, Severity, Vulnerability
from vulnscope.remediate import (
    Remediation,
    _build_update_command,
    _needs_reboot,
    _risk_level,
    apply_remediations,
    build_remediations,
)


def _make_vuln(
    name: str,
    ecosystem: str,
    version: str = "1.0",
    fixed_version: str | None = "1.1",
) -> Vulnerability:
    return Vulnerability(
        cve_id=f"CVE-2024-{hash(name) % 10000:04d}",
        aliases=[],
        title=f"Vuln in {name}",
        description="test",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cvss_vector=None,
        cwe_ids=[],
        affected_package=InstalledPackage(
            name=name,
            version=version,
            ecosystem=ecosystem,
            source=ecosystem,
            arch="amd64",
            purl=f"pkg:{ecosystem}/{name}@{version}",
        ),
        fixed_version=fixed_version,
        is_known_exploited=False,
        kev_due_date=None,
        references=[],
        published_date=None,
        source="osv",
    )


def _make_scan_result(vulns: list[Vulnerability]) -> ScanResult:
    return ScanResult(
        scan_id="test-scan",
        timestamp="2024-01-01T00:00:00Z",
        os_info={"id": "ubuntu", "version": "22.04"},
        total_packages=100,
        vulnerabilities=vulns,
        scan_duration_seconds=1.0,
    )


class TestNeedsReboot:
    def test_deb_kernel_needs_reboot(self):
        assert _needs_reboot("deb", "linux-image-5.15.0-generic") is True

    def test_deb_systemd_needs_reboot(self):
        assert _needs_reboot("deb", "systemd") is True

    def test_deb_libc6_needs_reboot(self):
        assert _needs_reboot("deb", "libc6") is True

    def test_deb_regular_no_reboot(self):
        assert _needs_reboot("deb", "curl") is False

    def test_non_deb_never_reboot(self):
        assert _needs_reboot("snap", "linux-image") is False
        assert _needs_reboot("pypi", "systemd") is False


class TestBuildUpdateCommand:
    def test_deb_command(self):
        cmd = _build_update_command("deb", "curl", "7.88.1-10+deb12u5")
        assert cmd == "sudo apt install curl=7.88.1-10+deb12u5 -y"

    def test_snap_command(self):
        cmd = _build_update_command("snap", "firefox", "125.0")
        assert cmd == "sudo snap refresh firefox"

    def test_flatpak_command(self):
        cmd = _build_update_command("flatpak", "org.gimp.GIMP", "2.10.36")
        assert cmd == "flatpak update org.gimp.GIMP -y"

    def test_pypi_command(self):
        cmd = _build_update_command("pypi", "requests", "2.31.0")
        assert cmd == "pip install --upgrade requests==2.31.0"

    def test_npm_command(self):
        cmd = _build_update_command("npm", "lodash", "4.17.21")
        assert cmd == "npm update -g lodash"

    def test_cargo_command(self):
        cmd = _build_update_command("cargo", "serde", "1.0.200")
        assert cmd == "cargo install serde --version 1.0.200"

    def test_brew_command(self):
        cmd = _build_update_command("brew", "openssl", "3.2.1")
        assert cmd == "brew upgrade openssl"

    def test_unknown_ecosystem_returns_none(self):
        assert _build_update_command("rpm", "pkg", "1.0") is None


class TestRiskLevel:
    def test_reboot_is_dangerous(self):
        assert _risk_level("deb", True) == "dangerous"

    def test_deb_without_reboot_is_caution(self):
        assert _risk_level("deb", False) == "caution"

    def test_other_ecosystems_are_safe(self):
        assert _risk_level("pypi", False) == "safe"
        assert _risk_level("snap", False) == "safe"


class TestBuildRemediations:
    def test_basic_build(self):
        vulns = [_make_vuln("curl", "deb")]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 1
        assert rems[0].package == "curl"
        assert rems[0].ecosystem == "deb"
        assert rems[0].fixed_version == "1.1"

    def test_skips_no_fixed_version(self):
        vulns = [_make_vuln("curl", "deb", fixed_version=None)]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 0

    def test_skips_unsupported_ecosystem(self):
        vulns = [_make_vuln("pkg", "rpm")]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 0

    def test_deduplicates_same_package(self):
        vulns = [
            _make_vuln("curl", "deb"),
            _make_vuln("curl", "deb"),  # same hash -> same CVE but same key
        ]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 1

    def test_multiple_ecosystems(self):
        vulns = [
            _make_vuln("requests", "pypi"),
            _make_vuln("curl", "deb"),
            _make_vuln("firefox", "snap"),
        ]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 3

    def test_kernel_marked_reboot(self):
        vulns = [_make_vuln("linux-image-5.15", "deb")]
        result = _make_scan_result(vulns)
        rems = build_remediations(result)
        assert len(rems) == 1
        assert rems[0].requires_reboot is True
        assert rems[0].risk_level == "dangerous"


class TestApplyRemediations:
    def test_successful_apply(self):
        rem = Remediation(
            package="curl",
            ecosystem="deb",
            current_version="7.88.1",
            fixed_version="7.88.2",
            update_command="sudo apt install curl=7.88.2 -y",
            requires_reboot=False,
            risk_level="caution",
        )

        def mock_runner(cmd):
            return SimpleNamespace(returncode=0, stdout="done", stderr="")

        results = apply_remediations([rem], runner=mock_runner)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].output == "done"

    def test_failed_apply(self):
        rem = Remediation(
            package="curl",
            ecosystem="deb",
            current_version="7.88.1",
            fixed_version="7.88.2",
            update_command="sudo apt install curl=7.88.2 -y",
            requires_reboot=False,
            risk_level="caution",
        )

        def mock_runner(cmd):
            return SimpleNamespace(returncode=1, stdout="", stderr="E: Unable to locate package")

        results = apply_remediations([rem], runner=mock_runner)
        assert len(results) == 1
        assert results[0].success is False
        assert "Unable to locate" in results[0].output

    def test_exception_handling(self):
        rem = Remediation(
            package="curl",
            ecosystem="deb",
            current_version="7.88.1",
            fixed_version="7.88.2",
            update_command="sudo apt install curl=7.88.2 -y",
            requires_reboot=False,
            risk_level="caution",
        )

        def mock_runner(cmd):
            raise RuntimeError("connection failed")

        results = apply_remediations([rem], runner=mock_runner)
        assert len(results) == 1
        assert results[0].success is False
        assert "connection failed" in results[0].output

    def test_multiple_remediations(self):
        rems = [
            Remediation(
                package="curl", ecosystem="deb",
                current_version="1.0", fixed_version="1.1",
                update_command="apt install curl=1.1",
                requires_reboot=False, risk_level="caution",
            ),
            Remediation(
                package="requests", ecosystem="pypi",
                current_version="2.28", fixed_version="2.31",
                update_command="pip install --upgrade requests==2.31",
                requires_reboot=False, risk_level="safe",
            ),
        ]

        call_log = []

        def mock_runner(cmd):
            call_log.append(cmd)
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        results = apply_remediations(rems, runner=mock_runner)
        assert len(results) == 2
        assert all(r.success for r in results)
        assert len(call_log) == 2
