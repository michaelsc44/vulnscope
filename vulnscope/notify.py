"""Desktop notifications for new vulnerabilities and auto-fix results."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys

from vulnscope.models import Vulnerability


def _severity_breakdown(vulns: list[Vulnerability]) -> str:
    counts: dict[str, int] = {}
    for v in vulns:
        label = v.severity.value.upper()
        counts[label] = counts.get(label, 0) + 1
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in counts:
            parts.append(f"{counts[sev]} {sev}")
    return ", ".join(parts)


def _send_custom(command: str, title: str, body: str) -> bool:
    """Run a user-provided notification command with title and body as arguments."""
    try:
        parts = shlex.split(command)
        subprocess.run(
            [*parts, title, body],
            check=True,
            timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return False


def send_notification(
    new_vulns: list[Vulnerability],
    *,
    custom_command: str | None = None,
) -> bool:
    """Send a desktop notification about new vulnerabilities. Returns True on success."""
    if not new_vulns:
        return False

    title = f"VulnScope: {len(new_vulns)} new vulnerability{'s' if len(new_vulns) != 1 else ''}"
    body = _severity_breakdown(new_vulns)

    kev_count = sum(1 for v in new_vulns if v.is_known_exploited)
    if kev_count:
        body += f"\n{kev_count} actively exploited (CISA KEV)"

    if custom_command:
        return _send_custom(custom_command, title, body)

    if sys.platform == "linux":
        return _notify_linux(title, body)
    elif sys.platform == "darwin":
        return _notify_macos(title, body)
    return False


def send_fix_notification(
    succeeded: int,
    failed: int,
    *,
    custom_command: str | None = None,
) -> bool:
    """Send a notification summarizing auto-fix results. Returns True on success."""
    total = succeeded + failed
    if total == 0:
        return False

    title = "VulnScope: Auto-fix results"
    parts = []
    if succeeded:
        parts.append(f"{succeeded} package{'s' if succeeded != 1 else ''} updated")
    if failed:
        parts.append(f"{failed} failed")
    body = ", ".join(parts)

    if custom_command:
        return _send_custom(custom_command, title, body)

    if sys.platform == "linux":
        return _notify_linux(title, body)
    elif sys.platform == "darwin":
        return _notify_macos(title, body)
    return False


def _notify_linux(title: str, body: str) -> bool:
    if not shutil.which("notify-send"):
        return False
    urgency = "critical"
    try:
        subprocess.run(
            ["notify-send", "--urgency", urgency, "--app-name", "VulnScope", title, body],
            check=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _notify_macos(title: str, body: str) -> bool:
    script = f'display notification "{body}" with title "{title}"'
    try:
        subprocess.run(
            ["osascript", "-e", script],
            check=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
