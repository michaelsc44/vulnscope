"""Tests for kernel livepatch detection and remediation."""

from types import SimpleNamespace

from vulnscope.inventory.livepatch import (
    LivepatchStatus,
    _parse_canonical_livepatch_output,
    _parse_kpatch_output,
    detect_livepatch,
)
from vulnscope.models import InstalledPackage, ScanResult, Severity, Vulnerability
from vulnscope.remediate import (
    _is_kernel_package,
    build_livepatch_remediations,
)


def _make_vuln(
    name: str,
    ecosystem: str,
    version: str = "5.15.0",
    fixed_version: str | None = "5.15.1",
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


class TestDetectLivepatch:
    def test_canonical_livepatch_available_and_enabled(self):
        def runner(args):
            if args == ["canonical-livepatch", "status"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="kernel: 5.15.0-100.110-generic\nfully-patched: true\nversion: 100.1\n",
                    stderr="",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="not found")

        status = detect_livepatch(runner=runner)
        assert status.available is True
        assert status.backend == "canonical-livepatch"
        assert status.enabled is True
        assert len(status.applied_patches) > 0

    def test_canonical_livepatch_installed_but_not_enabled(self):
        def runner(args):
            if args == ["canonical-livepatch", "status"]:
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Machine is not enabled. Please run 'sudo canonical-livepatch enable'.",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        status = detect_livepatch(runner=runner)
        assert status.available is True
        assert status.backend == "canonical-livepatch"
        assert status.enabled is False

    def test_kpatch_available(self):
        def runner(args):
            if args == ["canonical-livepatch", "status"]:
                return None
            if args == ["kpatch", "list"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="Loaded patch modules:\nkpatch_CVE_2024_1234 [enabled]\n\nInstalled patch modules:\nkpatch_CVE_2024_1234 (5.14.0-362.el9.x86_64)\n",
                    stderr="",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        status = detect_livepatch(runner=runner)
        assert status.available is True
        assert status.backend == "kpatch"
        assert status.enabled is True
        assert len(status.applied_patches) > 0

    def test_no_livepatch_available(self):
        def runner(args):
            return None

        status = detect_livepatch(runner=runner)
        assert status.available is False
        assert status.backend is None

    def test_kpatch_failure(self):
        def runner(args):
            if args == ["canonical-livepatch", "status"]:
                return None
            if args == ["kpatch", "list"]:
                return None
            return None

        status = detect_livepatch(runner=runner)
        assert status.available is False


class TestParseCanonicalLivepatchOutput:
    def test_parse_status_output(self):
        output = (
            "kernel: 5.15.0-100.110-generic\n"
            "fully-patched: true\n"
            "version: 100.1\n"
        )
        patches = _parse_canonical_livepatch_output(output)
        assert len(patches) == 1
        assert patches[0]["kernel"] == "5.15.0-100.110-generic"
        assert patches[0]["fully-patched"] == "true"

    def test_parse_empty_output(self):
        patches = _parse_canonical_livepatch_output("")
        assert patches == []

    def test_parse_multiple_sections(self):
        output = (
            "kernel: 5.15.0-100\n"
            "version: 100.1\n"
            "\n"
            "kernel: 5.15.0-101\n"
            "version: 101.1\n"
        )
        patches = _parse_canonical_livepatch_output(output)
        assert len(patches) == 2


class TestParseKpatchOutput:
    def test_parse_loaded_patches(self):
        output = (
            "Loaded patch modules:\n"
            "kpatch_CVE_2024_1234 [enabled]\n"
            "kpatch_CVE_2024_5678 [enabled]\n"
        )
        patches = _parse_kpatch_output(output)
        assert len(patches) == 2
        assert patches[0]["name"] == "kpatch_CVE_2024_1234"
        assert patches[0]["status"] == "[enabled]"

    def test_parse_empty_output(self):
        patches = _parse_kpatch_output("")
        assert patches == []

    def test_skips_header_lines(self):
        output = "Loaded patch modules:\nInstalled patch modules:\n"
        patches = _parse_kpatch_output(output)
        assert patches == []


class TestIsKernelPackage:
    def test_linux_image(self):
        assert _is_kernel_package("linux-image-5.15.0-generic") is True

    def test_linux_headers(self):
        assert _is_kernel_package("linux-headers-5.15.0") is True

    def test_kernel_core(self):
        assert _is_kernel_package("kernel-core") is True

    def test_kernel_modules(self):
        assert _is_kernel_package("kernel-modules-5.14") is True

    def test_non_kernel(self):
        assert _is_kernel_package("curl") is False
        assert _is_kernel_package("openssl") is False

    def test_kernel_exact(self):
        assert _is_kernel_package("kernel") is True


class TestBuildLivepatchRemediations:
    def test_builds_canonical_livepatch_remediation(self):
        vulns = [_make_vuln("linux-image-5.15.0", "deb")]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=True,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 1
        assert rems[0].update_command == "sudo canonical-livepatch refresh"
        assert rems[0].requires_reboot is False
        assert rems[0].risk_level == "safe"

    def test_builds_kpatch_remediation(self):
        vulns = [_make_vuln("kernel-core", "rpm", version="5.14.0")]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="kpatch",
            enabled=True,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 1
        assert rems[0].update_command == "sudo kpatch load"
        assert rems[0].requires_reboot is False

    def test_skips_non_kernel_packages(self):
        vulns = [_make_vuln("curl", "deb")]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=True,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 0

    def test_returns_empty_when_not_available(self):
        vulns = [_make_vuln("linux-image-5.15.0", "deb")]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(available=False, backend=None)
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 0

    def test_returns_empty_when_not_enabled(self):
        vulns = [_make_vuln("linux-image-5.15.0", "deb")]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=False,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 0

    def test_deduplicates_kernel_packages(self):
        vulns = [
            _make_vuln("linux-image-5.15.0", "deb"),
            _make_vuln("linux-image-5.15.0", "deb"),
        ]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=True,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 1

    def test_skips_no_fixed_version(self):
        vulns = [_make_vuln("linux-image-5.15.0", "deb", fixed_version=None)]
        result = _make_scan_result(vulns)
        lp_status = LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=True,
        )
        rems = build_livepatch_remediations(result, livepatch_status=lp_status)
        assert len(rems) == 0
