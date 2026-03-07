"""Auto-remediation engine for vulnscope."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from vulnscope.models import ScanResult

REBOOT_PACKAGES = frozenset({
    "linux-image",
    "linux-headers",
    "linux-generic",
    "linux-base",
    "systemd",
    "libc6",
    "libc-bin",
    "glibc",
})


def _needs_reboot(ecosystem: str, package_name: str) -> bool:
    if ecosystem != "deb":
        return False
    name = package_name.lower()
    return any(name == rb or name.startswith(rb + "-") for rb in REBOOT_PACKAGES)


@dataclass
class Remediation:
    package: str
    ecosystem: str
    current_version: str
    fixed_version: str
    update_command: str
    requires_reboot: bool
    risk_level: str  # "safe", "caution", "dangerous"


def _risk_level(ecosystem: str, requires_reboot: bool) -> str:
    if requires_reboot:
        return "dangerous"
    if ecosystem == "deb":
        return "caution"
    return "safe"


def _build_update_command(ecosystem: str, package: str, fixed_version: str) -> str | None:
    commands = {
        "deb": f"sudo apt install {package}={fixed_version} -y",
        "snap": f"sudo snap refresh {package}",
        "flatpak": f"flatpak update {package} -y",
        "pypi": f"pip install --upgrade {package}=={fixed_version}",
        "npm": f"npm update -g {package}",
        "cargo": f"cargo install {package} --version {fixed_version}",
        "brew": f"brew upgrade {package}",
    }
    return commands.get(ecosystem)


def build_remediations(scan_result: ScanResult) -> list[Remediation]:
    remediations: list[Remediation] = []
    seen: set[str] = set()

    for vuln in scan_result.vulnerabilities:
        if not vuln.fixed_version:
            continue

        pkg = vuln.affected_package
        key = f"{pkg.ecosystem}:{pkg.name}:{vuln.fixed_version}"
        if key in seen:
            continue
        seen.add(key)

        cmd = _build_update_command(pkg.ecosystem, pkg.name, vuln.fixed_version)
        if cmd is None:
            continue

        reboot = _needs_reboot(pkg.ecosystem, pkg.name)
        remediations.append(Remediation(
            package=pkg.name,
            ecosystem=pkg.ecosystem,
            current_version=pkg.version,
            fixed_version=vuln.fixed_version,
            update_command=cmd,
            requires_reboot=reboot,
            risk_level=_risk_level(pkg.ecosystem, reboot),
        ))

    return remediations


@dataclass
class RemediationResult:
    remediation: Remediation
    success: bool
    output: str


def apply_remediations(
    remediations: list[Remediation],
    *,
    runner: object | None = None,
) -> list[RemediationResult]:
    results: list[RemediationResult] = []
    for rem in remediations:
        try:
            if runner is not None:
                cp = runner(rem.update_command)  # type: ignore[operator]
            else:
                cp = subprocess.run(
                    rem.update_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            success = cp.returncode == 0
            output = cp.stdout if success else cp.stderr
        except subprocess.TimeoutExpired:
            success = False
            output = "Command timed out after 300 seconds"
        except Exception as exc:
            success = False
            output = str(exc)

        results.append(RemediationResult(
            remediation=rem,
            success=success,
            output=output.strip() if output else "",
        ))
    return results


def print_remediation_table(
    remediations: list[Remediation],
    *,
    dry_run: bool = True,
) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()

    if not remediations:
        console.print("[green]No fixable vulnerabilities found.[/green]")
        return

    title = "Proposed Updates (dry run)" if dry_run else "Applying Updates"
    table = Table(title=title)
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Current")
    table.add_column("Fixed")
    table.add_column("Reboot?")
    table.add_column("Risk")
    table.add_column("Command")

    risk_colors = {"safe": "green", "caution": "yellow", "dangerous": "red"}

    for rem in remediations:
        reboot_str = "[red]Yes[/red]" if rem.requires_reboot else "No"
        color = risk_colors.get(rem.risk_level, "white")
        table.add_row(
            rem.package,
            rem.ecosystem,
            rem.current_version,
            rem.fixed_version,
            reboot_str,
            f"[{color}]{rem.risk_level}[/{color}]",
            rem.update_command,
        )

    console.print(table)
    console.print(f"\n[bold]{len(remediations)} package(s) to update[/bold]")


def print_results_table(results: list[RemediationResult]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Update Results")
    table.add_column("Package")
    table.add_column("Status")
    table.add_column("Output")

    succeeded = 0
    for res in results:
        if res.success:
            status = "[green]OK[/green]"
            succeeded += 1
        else:
            status = "[red]FAILED[/red]"
        output = res.output[:80] if res.output else ""
        table.add_row(res.remediation.package, status, output)

    console.print(table)
    console.print(
        f"\n[bold]{succeeded}/{len(results)} updates succeeded[/bold]"
    )
