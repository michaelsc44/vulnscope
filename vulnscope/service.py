"""Systemd / launchd service management for vulnscope watch."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SYSTEMD_UNIT = """\
[Unit]
Description=VulnScope vulnerability watch daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"""

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vulnscope.watch</string>
    <key>ProgramArguments</key>
    <array>
        <string>{vulnscope_bin}</string>
        <string>watch</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/vulnscope-watch.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/vulnscope-watch.log</string>
</dict>
</plist>
"""

SYSTEMD_SERVICE_NAME = "vulnscope-watch.service"
LAUNCHD_LABEL = "com.vulnscope.watch"


def _find_vulnscope_bin() -> str:
    path = shutil.which("vulnscope")
    if path:
        return path
    return str(Path(sys.executable).parent / "vulnscope")


def _systemd_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / SYSTEMD_SERVICE_NAME


def _launchd_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def install_service(start: bool = False) -> str:
    """Install the watch service. Returns a status message."""
    if sys.platform == "darwin":
        return _install_launchd(start)
    return _install_systemd(start)


def uninstall_service() -> str:
    """Uninstall the watch service. Returns a status message."""
    if sys.platform == "darwin":
        return _uninstall_launchd()
    return _uninstall_systemd()


def _install_systemd(start: bool) -> str:
    vulnscope_bin = _find_vulnscope_bin()
    exec_start = f"{vulnscope_bin} watch start --foreground"
    unit_content = SYSTEMD_UNIT.format(exec_start=exec_start)

    unit_path = _systemd_unit_path()
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(unit_content)

    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["systemctl", "--user", "enable", SYSTEMD_SERVICE_NAME],
        check=True,
        capture_output=True,
    )

    msg = f"Service installed and enabled: {unit_path}"
    if start:
        subprocess.run(
            ["systemctl", "--user", "start", SYSTEMD_SERVICE_NAME],
            check=True,
            capture_output=True,
        )
        msg += "\nService started."
    return msg


def _uninstall_systemd() -> str:
    unit_path = _systemd_unit_path()
    if not unit_path.exists():
        return "Service is not installed."

    subprocess.run(
        ["systemctl", "--user", "stop", SYSTEMD_SERVICE_NAME],
        capture_output=True,
    )
    subprocess.run(
        ["systemctl", "--user", "disable", SYSTEMD_SERVICE_NAME],
        capture_output=True,
    )
    unit_path.unlink()
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True,
    )
    return f"Service disabled and removed: {unit_path}"


def _install_launchd(start: bool) -> str:
    vulnscope_bin = _find_vulnscope_bin()
    log_dir = Path.home() / "Library" / "Logs"
    plist_content = LAUNCHD_PLIST.format(
        vulnscope_bin=vulnscope_bin,
        log_dir=log_dir,
    )

    plist_path = _launchd_plist_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(plist_content)

    msg = f"Service installed: {plist_path}"
    if start:
        subprocess.run(
            ["launchctl", "load", str(plist_path)],
            check=True,
            capture_output=True,
        )
        msg += "\nService loaded."
    return msg


def _uninstall_launchd() -> str:
    plist_path = _launchd_plist_path()
    if not plist_path.exists():
        return "Service is not installed."

    subprocess.run(
        ["launchctl", "unload", str(plist_path)],
        capture_output=True,
    )
    plist_path.unlink()
    return f"Service unloaded and removed: {plist_path}"
