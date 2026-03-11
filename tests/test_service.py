"""Tests for systemd/launchd service install/uninstall."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from vulnscope.cli import main
from vulnscope.service import (
    LAUNCHD_LABEL,
    SYSTEMD_SERVICE_NAME,
    _find_vulnscope_bin,
    install_service,
    uninstall_service,
)


class TestFindBin:
    @patch("vulnscope.service.shutil.which", return_value="/usr/local/bin/vulnscope")
    def test_finds_on_path(self, mock_which):
        assert _find_vulnscope_bin() == "/usr/local/bin/vulnscope"

    @patch("vulnscope.service.shutil.which", return_value=None)
    def test_falls_back_to_sys_executable(self, mock_which):
        with patch("vulnscope.service.sys") as mock_sys:
            mock_sys.executable = "/usr/bin/python3"
            result = _find_vulnscope_bin()
            assert result.endswith("vulnscope")
            assert "/usr/bin/" in result


class TestInstallSystemd:
    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/bin/vulnscope")
    def test_install_creates_unit_file(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            msg = install_service(start=False)

        assert unit_path.exists()
        content = unit_path.read_text()
        assert "Type=simple" in content
        assert "vulnscope watch start --foreground" in content
        assert "Restart=on-failure" in content
        assert "installed and enabled" in msg

        assert mock_run.call_count == 2
        daemon_reload = mock_run.call_args_list[0]
        assert "daemon-reload" in daemon_reload[0][0]
        enable_call = mock_run.call_args_list[1]
        assert "enable" in enable_call[0][0]

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/bin/vulnscope")
    def test_install_with_start(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            msg = install_service(start=True)

        assert "started" in msg.lower()
        assert mock_run.call_count == 3
        start_call = mock_run.call_args_list[2]
        assert "start" in start_call[0][0]

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    def test_uninstall_removes_unit(self, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        unit_path.write_text("[Unit]\n")
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            msg = uninstall_service()

        assert not unit_path.exists()
        assert "disabled and removed" in msg
        assert mock_run.call_count == 3  # stop, disable, daemon-reload

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    def test_uninstall_not_installed(self, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            msg = uninstall_service()

        assert "not installed" in msg
        mock_run.assert_not_called()


class TestInstallLaunchd:
    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/local/bin/vulnscope")
    def test_install_creates_plist(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "darwin"
        plist_path = tmp_path / f"{LAUNCHD_LABEL}.plist"
        with patch("vulnscope.service._launchd_plist_path", return_value=plist_path):
            msg = install_service(start=False)

        assert plist_path.exists()
        content = plist_path.read_text()
        assert "<key>Label</key>" in content
        assert "com.vulnscope.watch" in content
        assert "/usr/local/bin/vulnscope" in content
        assert "installed" in msg
        mock_run.assert_not_called()

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/local/bin/vulnscope")
    def test_install_with_start_loads(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "darwin"
        plist_path = tmp_path / f"{LAUNCHD_LABEL}.plist"
        with patch("vulnscope.service._launchd_plist_path", return_value=plist_path):
            msg = install_service(start=True)

        assert "loaded" in msg.lower()
        mock_run.assert_called_once()
        assert "launchctl" in mock_run.call_args[0][0][0]

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    def test_uninstall_removes_plist(self, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "darwin"
        plist_path = tmp_path / f"{LAUNCHD_LABEL}.plist"
        plist_path.write_text("<plist/>")
        with patch("vulnscope.service._launchd_plist_path", return_value=plist_path):
            msg = uninstall_service()

        assert not plist_path.exists()
        assert "unloaded and removed" in msg

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    def test_uninstall_not_installed(self, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "darwin"
        plist_path = tmp_path / f"{LAUNCHD_LABEL}.plist"
        with patch("vulnscope.service._launchd_plist_path", return_value=plist_path):
            msg = uninstall_service()

        assert "not installed" in msg


class TestServiceCLI:
    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/bin/vulnscope")
    def test_install_service_command(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            runner = CliRunner()
            result = runner.invoke(main, ["watch", "install-service"])
        assert result.exit_code == 0
        assert "installed" in result.output.lower()

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    @patch("vulnscope.service.shutil.which", return_value="/usr/bin/vulnscope")
    def test_install_service_with_start(self, mock_which, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            runner = CliRunner()
            result = runner.invoke(main, ["watch", "install-service", "--start"])
        assert result.exit_code == 0
        assert "started" in result.output.lower()

    @patch("vulnscope.service.subprocess.run")
    @patch("vulnscope.service.sys")
    def test_uninstall_service_command(self, mock_sys, mock_run, tmp_path):
        mock_sys.platform = "linux"
        unit_path = tmp_path / SYSTEMD_SERVICE_NAME
        unit_path.write_text("[Unit]\n")
        with patch("vulnscope.service._systemd_unit_path", return_value=unit_path):
            runner = CliRunner()
            result = runner.invoke(main, ["watch", "uninstall-service"])
        assert result.exit_code == 0
        assert "removed" in result.output.lower()
