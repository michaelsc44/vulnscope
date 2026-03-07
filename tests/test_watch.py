"""Tests for scan_store, notify, and watch CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from vulnscope.cli import main
from vulnscope.models import InstalledPackage, ScanResult, Severity, Vulnerability
from vulnscope.notify import _severity_breakdown, send_notification
from vulnscope.scan_store import (
    diff_scans,
    load_latest_scan,
    result_from_dict,
    result_to_dict,
    save_scan,
)


def _make_vuln(cve_id: str, pkg_name: str = "testpkg", severity: str = "high") -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        aliases=[],
        title=f"Test {cve_id}",
        description="desc",
        severity=Severity(severity),
        cvss_score=7.5,
        cvss_vector=None,
        cwe_ids=[],
        affected_package=InstalledPackage(
            name=pkg_name, version="1.0", ecosystem="pypi", source="pip", arch=None, purl=f"pkg:pypi/{pkg_name}@1.0",
        ),
        fixed_version="1.1",
        is_known_exploited=False,
        kev_due_date=None,
        references=[],
        published_date=None,
        source="osv",
    )


def _make_result(vulns: list[Vulnerability] | None = None) -> ScanResult:
    return ScanResult(
        scan_id="test-id",
        timestamp="2025-01-01T00:00:00+00:00",
        os_info={"id": "ubuntu", "version": "22.04"},
        total_packages=100,
        vulnerabilities=vulns or [],
        scan_duration_seconds=5.0,
    )


class TestScanStore:
    def test_round_trip(self, tmp_path: Path):
        result = _make_result([_make_vuln("CVE-2024-0001")])
        data = result_to_dict(result)
        restored = result_from_dict(data)
        assert restored.scan_id == "test-id"
        assert len(restored.vulnerabilities) == 1
        assert restored.vulnerabilities[0].cve_id == "CVE-2024-0001"
        assert restored.vulnerabilities[0].severity == Severity.HIGH

    def test_save_and_load(self, tmp_path: Path):
        result = _make_result([_make_vuln("CVE-2024-0002")])
        with patch("vulnscope.scan_store.SCANS_DIR", tmp_path):
            path = save_scan(result)
            assert path.exists()
            loaded = load_latest_scan()
            assert loaded is not None
            assert loaded.vulnerabilities[0].cve_id == "CVE-2024-0002"

    def test_load_latest_empty(self, tmp_path: Path):
        with patch("vulnscope.scan_store.SCANS_DIR", tmp_path):
            assert load_latest_scan() is None

    def test_load_latest_no_dir(self, tmp_path: Path):
        with patch("vulnscope.scan_store.SCANS_DIR", tmp_path / "nonexistent"):
            assert load_latest_scan() is None

    def test_diff_scans_new_vulns(self):
        prev = _make_result([_make_vuln("CVE-2024-0001")])
        curr = _make_result([_make_vuln("CVE-2024-0001"), _make_vuln("CVE-2024-0002")])
        new = diff_scans(prev, curr)
        assert len(new) == 1
        assert new[0].cve_id == "CVE-2024-0002"

    def test_diff_scans_no_new(self):
        prev = _make_result([_make_vuln("CVE-2024-0001")])
        curr = _make_result([_make_vuln("CVE-2024-0001")])
        assert diff_scans(prev, curr) == []

    def test_diff_scans_all_new(self):
        prev = _make_result([])
        curr = _make_result([_make_vuln("CVE-2024-0001")])
        assert len(diff_scans(prev, curr)) == 1

    def test_diff_same_cve_different_package(self):
        prev = _make_result([_make_vuln("CVE-2024-0001", pkg_name="pkg-a")])
        curr = _make_result([_make_vuln("CVE-2024-0001", pkg_name="pkg-b")])
        new = diff_scans(prev, curr)
        assert len(new) == 1
        assert new[0].affected_package.name == "pkg-b"


class TestNotify:
    def test_severity_breakdown(self):
        vulns = [
            _make_vuln("CVE-1", severity="critical"),
            _make_vuln("CVE-2", severity="critical"),
            _make_vuln("CVE-3", severity="high"),
        ]
        text = _severity_breakdown(vulns)
        assert "2 CRITICAL" in text
        assert "1 HIGH" in text

    def test_send_notification_empty(self):
        assert send_notification([]) is False

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value="/usr/bin/notify-send")
    @patch("vulnscope.notify.subprocess.run")
    def test_send_linux(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        vulns = [_make_vuln("CVE-2024-0001", severity="critical")]
        result = send_notification(vulns)
        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "notify-send"
        assert "1 new vulnerability" in args[-2]

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.subprocess.run")
    def test_send_macos(self, mock_run, mock_sys):
        mock_sys.platform = "darwin"
        vulns = [_make_vuln("CVE-1"), _make_vuln("CVE-2")]
        result = send_notification(vulns)
        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "osascript"

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value=None)
    def test_send_linux_no_notifysend(self, mock_which, mock_sys):
        mock_sys.platform = "linux"
        vulns = [_make_vuln("CVE-1")]
        assert send_notification(vulns) is False


class TestWatchCLI:
    def test_watch_status_not_running(self, tmp_path: Path):
        runner = CliRunner()
        with patch("vulnscope.cli._pid_file", return_value=tmp_path / "watch.pid"):
            result = runner.invoke(main, ["watch", "status"])
            assert "not running" in result.output

    def test_watch_stop_not_running(self, tmp_path: Path):
        runner = CliRunner()
        with patch("vulnscope.cli._pid_file", return_value=tmp_path / "watch.pid"):
            result = runner.invoke(main, ["watch", "stop"])
            assert "No watch daemon" in result.output

    def test_watch_status_running(self, tmp_path: Path):
        import os

        pid_file = tmp_path / "watch.pid"
        pid_file.write_text(str(os.getpid()))
        runner = CliRunner()
        with patch("vulnscope.cli._pid_file", return_value=pid_file):
            result = runner.invoke(main, ["watch", "status"])
            assert "running" in result.output
            assert str(os.getpid()) in result.output
