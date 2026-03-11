"""Tests for scan_store, notify, and watch CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vulnscope.cli import _auto_fix_vulns, main
from vulnscope.models import InstalledPackage, ScanResult, Severity, Vulnerability
from vulnscope.notify import (
    _send_custom,
    _severity_breakdown,
    send_fix_notification,
    send_notification,
)
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

    @patch("vulnscope.notify.subprocess.run")
    def test_send_notification_custom_command(self, mock_run):
        vulns = [_make_vuln("CVE-1", severity="critical")]
        result = send_notification(vulns, custom_command="/usr/local/bin/my-notifier")
        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "/usr/local/bin/my-notifier"
        assert "1 new vulnerability" in args[1]

    @patch("vulnscope.notify.subprocess.run")
    def test_send_custom_command_with_args(self, mock_run):
        result = _send_custom("curl -X POST https://hooks.example.com/notify", "title", "body")
        assert result is True
        args = mock_run.call_args[0][0]
        assert args == ["curl", "-X", "POST", "https://hooks.example.com/notify", "title", "body"]

    @patch("vulnscope.notify.subprocess.run", side_effect=FileNotFoundError)
    def test_send_custom_command_not_found(self, mock_run):
        result = _send_custom("nonexistent-cmd", "title", "body")
        assert result is False


class TestFixNotification:
    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value="/usr/bin/notify-send")
    @patch("vulnscope.notify.subprocess.run")
    def test_fix_notification_success_only(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        result = send_fix_notification(3, 0)
        assert result is True
        args = mock_run.call_args[0][0]
        assert "Auto-fix results" in args[-2]
        assert "3 packages updated" in args[-1]
        assert "failed" not in args[-1]

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value="/usr/bin/notify-send")
    @patch("vulnscope.notify.subprocess.run")
    def test_fix_notification_with_failures(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        result = send_fix_notification(3, 2)
        assert result is True
        args = mock_run.call_args[0][0]
        assert "3 packages updated" in args[-1]
        assert "2 failed" in args[-1]

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value="/usr/bin/notify-send")
    @patch("vulnscope.notify.subprocess.run")
    def test_fix_notification_all_failed(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        result = send_fix_notification(0, 2)
        assert result is True
        body = mock_run.call_args[0][0][-1]
        assert "2 failed" in body
        assert "updated" not in body

    def test_fix_notification_no_results(self):
        assert send_fix_notification(0, 0) is False

    @patch("vulnscope.notify.subprocess.run")
    def test_fix_notification_custom_command(self, mock_run):
        result = send_fix_notification(5, 1, custom_command="./my-webhook.sh")
        assert result is True
        args = mock_run.call_args[0][0]
        assert args[0] == "./my-webhook.sh"
        assert "Auto-fix results" in args[1]
        assert "5 packages updated" in args[2]

    @patch("vulnscope.notify.sys")
    @patch("vulnscope.notify.shutil.which", return_value="/usr/bin/notify-send")
    @patch("vulnscope.notify.subprocess.run")
    def test_fix_notification_singular(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        send_fix_notification(1, 0)
        body = mock_run.call_args[0][0][-1]
        assert "1 package updated" in body
        assert "packages" not in body


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


class TestAutoFix:
    def _make_vuln_with_fix(self, cve_id: str, pkg_name: str = "testpkg", ecosystem: str = "pypi") -> Vulnerability:
        return Vulnerability(
            cve_id=cve_id,
            aliases=[],
            title=f"Test {cve_id}",
            description="desc",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector=None,
            cwe_ids=[],
            affected_package=InstalledPackage(
                name=pkg_name, version="1.0", ecosystem=ecosystem, source=ecosystem, arch=None, purl=f"pkg:{ecosystem}/{pkg_name}@1.0",
            ),
            fixed_version="1.1",
            is_known_exploited=False,
            kev_due_date=None,
            references=[],
            published_date=None,
            source="osv",
        )

    def _make_result_with_vulns(self, vulns: list[Vulnerability]) -> ScanResult:
        return ScanResult(
            scan_id="test-id",
            timestamp="2025-01-01T00:00:00+00:00",
            os_info={"id": "ubuntu", "version": "22.04"},
            total_packages=100,
            vulnerabilities=vulns,
            scan_duration_seconds=5.0,
        )

    def test_auto_fix_applies_remediations(self, tmp_path: Path):
        vulns = [self._make_vuln_with_fix("CVE-2024-0001")]
        result = self._make_result_with_vulns(vulns)

        mock_cp = SimpleNamespace(returncode=0, stdout="updated", stderr="")
        with (
            patch("vulnscope.remediate.subprocess.run", return_value=mock_cp),
            patch("vulnscope.notify.send_fix_notification") as mock_fix_notify,
        ):
            _auto_fix_vulns(result, tmp_path)
            mock_fix_notify.assert_called_once_with(1, 0, custom_command=None)

        log_dir = tmp_path / "autofix_logs"
        assert log_dir.exists()
        log_files = list(log_dir.glob("autofix_*.json"))
        assert len(log_files) == 1

        log_data = json.loads(log_files[0].read_text())
        assert log_data["remediations_attempted"] == 1
        assert log_data["succeeded"] == 1
        assert log_data["failed"] == 0
        assert log_data["details"][0]["package"] == "testpkg"
        assert log_data["details"][0]["success"] is True

    def test_auto_fix_skips_reboot_packages(self, tmp_path: Path):
        vulns = [self._make_vuln_with_fix("CVE-2024-0001", pkg_name="linux-image-5.15", ecosystem="deb")]
        result = self._make_result_with_vulns(vulns)

        _auto_fix_vulns(result, tmp_path)

        log_dir = tmp_path / "autofix_logs"
        assert not log_dir.exists()

    def test_auto_fix_logs_failures(self, tmp_path: Path):
        vulns = [self._make_vuln_with_fix("CVE-2024-0001")]
        result = self._make_result_with_vulns(vulns)

        mock_cp = SimpleNamespace(returncode=1, stdout="", stderr="error occurred")
        with (
            patch("vulnscope.remediate.subprocess.run", return_value=mock_cp),
            patch("vulnscope.notify.send_fix_notification") as mock_fix_notify,
        ):
            _auto_fix_vulns(result, tmp_path)
            mock_fix_notify.assert_called_once_with(0, 1, custom_command=None)

        log_files = list((tmp_path / "autofix_logs").glob("autofix_*.json"))
        log_data = json.loads(log_files[0].read_text())
        assert log_data["failed"] == 1
        assert log_data["details"][0]["success"] is False

    def test_auto_fix_no_fixable_vulns(self, tmp_path: Path):
        vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            aliases=[],
            title="Test",
            description="desc",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector=None,
            cwe_ids=[],
            affected_package=InstalledPackage(
                name="pkg", version="1.0", ecosystem="pypi", source="pypi", arch=None, purl="pkg:pypi/pkg@1.0",
            ),
            fixed_version=None,
            is_known_exploited=False,
            kev_due_date=None,
            references=[],
            published_date=None,
            source="osv",
        )
        result = self._make_result_with_vulns([vuln])

        _auto_fix_vulns(result, tmp_path)

        log_dir = tmp_path / "autofix_logs"
        assert not log_dir.exists()

    def test_auto_fix_sends_notification_with_custom_command(self, tmp_path: Path):
        vulns = [self._make_vuln_with_fix("CVE-2024-0001")]
        result = self._make_result_with_vulns(vulns)

        mock_cp = SimpleNamespace(returncode=0, stdout="updated", stderr="")
        with (
            patch("vulnscope.remediate.subprocess.run", return_value=mock_cp),
            patch("vulnscope.notify.send_fix_notification") as mock_fix_notify,
        ):
            _auto_fix_vulns(result, tmp_path, notify_command="./webhook.sh")
            mock_fix_notify.assert_called_once_with(1, 0, custom_command="./webhook.sh")

    def test_watch_loop_passes_notify_command(self):
        """Test that _watch_loop passes notify_command to send_notification and _auto_fix_vulns."""
        vuln = self._make_vuln_with_fix("CVE-2024-0001")
        prev_result = self._make_result_with_vulns([])
        curr_result = self._make_result_with_vulns([vuln])

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                raise KeyboardInterrupt

        with (
            patch("vulnscope.cli.asyncio.run", return_value=curr_result),
            patch("vulnscope.cli.load_config", return_value={}),
            patch("vulnscope.cli.build_scan_config", return_value=MagicMock()),
            patch("vulnscope.scan_store.load_latest_scan", return_value=prev_result),
            patch("vulnscope.scan_store.save_scan"),
            patch("vulnscope.notify.send_notification") as mock_notify,
            patch("vulnscope.cli._auto_fix_vulns") as mock_auto_fix,
            patch("vulnscope.cli.time.sleep", side_effect=fake_sleep),
        ):
            from vulnscope.cli import _watch_loop
            try:
                _watch_loop(1, auto_fix=True, notify_command="./custom.sh")
            except KeyboardInterrupt:
                pass

            mock_notify.assert_called_once()
            assert mock_notify.call_args[1]["custom_command"] == "./custom.sh"
            mock_auto_fix.assert_called_once()
            assert mock_auto_fix.call_args[1]["notify_command"] == "./custom.sh"

    def test_watch_loop_calls_auto_fix(self):
        """Test that _watch_loop calls _auto_fix_vulns when auto_fix=True and new vulns found."""
        vuln = self._make_vuln_with_fix("CVE-2024-0001")
        prev_result = self._make_result_with_vulns([])
        curr_result = self._make_result_with_vulns([vuln])

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                raise KeyboardInterrupt

        with (
            patch("vulnscope.cli.asyncio.run", return_value=curr_result),
            patch("vulnscope.cli.load_config", return_value={}),
            patch("vulnscope.cli.build_scan_config", return_value=MagicMock()),
            patch("vulnscope.scan_store.load_latest_scan", return_value=prev_result),
            patch("vulnscope.scan_store.save_scan"),
            patch("vulnscope.notify.send_notification") as mock_notify,
            patch("vulnscope.cli._auto_fix_vulns") as mock_auto_fix,
            patch("vulnscope.cli.time.sleep", side_effect=fake_sleep),
        ):
            from vulnscope.cli import _watch_loop
            try:
                _watch_loop(1, auto_fix=True)
            except KeyboardInterrupt:
                pass

            mock_notify.assert_called_once()
            mock_auto_fix.assert_called_once()

    def test_watch_loop_no_auto_fix_by_default(self):
        """Test that _watch_loop does NOT call _auto_fix_vulns when auto_fix=False."""
        vuln = self._make_vuln_with_fix("CVE-2024-0001")
        prev_result = self._make_result_with_vulns([])
        curr_result = self._make_result_with_vulns([vuln])

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                raise KeyboardInterrupt

        with (
            patch("vulnscope.cli.asyncio.run", return_value=curr_result),
            patch("vulnscope.cli.load_config", return_value={}),
            patch("vulnscope.cli.build_scan_config", return_value=MagicMock()),
            patch("vulnscope.scan_store.load_latest_scan", return_value=prev_result),
            patch("vulnscope.scan_store.save_scan"),
            patch("vulnscope.notify.send_notification"),
            patch("vulnscope.cli._auto_fix_vulns") as mock_auto_fix,
            patch("vulnscope.cli.time.sleep", side_effect=fake_sleep),
        ):
            from vulnscope.cli import _watch_loop
            try:
                _watch_loop(1, auto_fix=False)
            except KeyboardInterrupt:
                pass

            mock_auto_fix.assert_not_called()
