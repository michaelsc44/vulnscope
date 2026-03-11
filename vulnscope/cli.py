import asyncio
import os
import signal
import subprocess
import sys
import time

import click

from vulnscope import __version__
from vulnscope.config import build_scan_config, load_config


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="vulnscope")
@click.pass_context
def main(ctx: click.Context) -> None:
    """VulnScope — CLI vulnerability scanner for Linux systems."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.option("--no-ui", is_flag=True, help="Non-interactive table output (no TUI)")
@click.option("--json", "output_json", is_flag=True, help="JSON output to stdout")
@click.option("--csv", "output_csv", is_flag=True, help="CSV output to stdout")
@click.option("--sarif", is_flag=True, help="SARIF 2.1.0 output to stdout")
@click.option("--html", "html_file", type=click.Path(), default=None, help="Write HTML report to file")
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Only show vulnerabilities at or above this severity",
)
@click.option(
    "--ecosystem",
    multiple=True,
    help="Filter to specific ecosystems (deb, rpm, pypi, npm, cargo, apk)",
)
@click.option("--no-cache", is_flag=True, help="Bypass local cache, fetch fresh data")
@click.option("--scan-docker-contents", is_flag=True, help="Scan packages inside Docker images")
@click.option("--summary-only", is_flag=True, help="Show only the scan summary (no full table)")
def scan(
    no_ui: bool,
    output_json: bool,
    output_csv: bool,
    sarif: bool,
    html_file: str | None,
    severity: str | None,
    ecosystem: tuple[str, ...],
    no_cache: bool,
    scan_docker_contents: bool,
    summary_only: bool,
) -> None:
    """Scan system for vulnerabilities."""
    raw_config = load_config()
    config = build_scan_config(
        raw_config,
        no_cache=no_cache,
        scan_docker_contents=scan_docker_contents,
        severity_filter=severity,
        ecosystems=list(ecosystem) if ecosystem else None,
    )

    from vulnscope.scanner import run_scan

    non_interactive = no_ui or output_json or output_csv or sarif or bool(html_file) or summary_only

    try:
        result = asyncio.run(run_scan(config))
    except KeyboardInterrupt:
        click.echo("\nScan cancelled.", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Scan error: {e}", err=True)
        sys.exit(2)

    if output_json:
        from vulnscope.export.json_export import to_json
        click.echo(to_json(result))
    elif output_csv:
        from vulnscope.export.csv_export import to_csv
        click.echo(to_csv(result))
    elif sarif:
        from vulnscope.export.sarif_export import to_sarif
        click.echo(to_sarif(result))
    elif html_file:
        import pathlib

        from vulnscope.export.html_export import to_html
        pathlib.Path(html_file).write_text(to_html(result))
        click.echo(f"HTML report written to {html_file}")
    elif summary_only:
        from vulnscope.ui.tables import print_summary
        print_summary(result)
    elif non_interactive:
        from vulnscope.ui.tables import print_results, print_summary
        print_results(result, severity_filter=severity)
        print_summary(result)
    else:
        from vulnscope.ui.app import VulnScopeApp
        app = VulnScopeApp(result)
        app.run()

    if result.vulnerabilities:
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.option(
    "--ecosystem",
    multiple=True,
    help="Filter to specific ecosystems",
)
def inventory(ecosystem: tuple[str, ...]) -> None:
    """Show installed packages without vulnerability lookup."""
    from rich.console import Console
    from rich.table import Table

    from vulnscope.inventory.apk import ApkCollector
    from vulnscope.inventory.brew import BrewCollector
    from vulnscope.inventory.cargo_packages import CargoCollector
    from vulnscope.inventory.dpkg import DpkgCollector
    from vulnscope.inventory.npm_packages import NpmCollector
    from vulnscope.inventory.os_info import get_os_info
    from vulnscope.inventory.pacman import PacmanCollector
    from vulnscope.inventory.pip_packages import PipCollector
    from vulnscope.inventory.rpm import RpmCollector
    from vulnscope.inventory.snap import SnapCollector

    console = Console()
    os_info = get_os_info()
    console.print(f"[bold]OS:[/bold] {os_info.pretty_name} / kernel {os_info.kernel_version}")

    collectors = [
        DpkgCollector(distro_id=os_info.id),
        RpmCollector(distro_id=os_info.id),
        ApkCollector(),
        PipCollector(),
        NpmCollector(),
        CargoCollector(),
        SnapCollector(),
        PacmanCollector(),
        BrewCollector(),
    ]

    table = Table(title="Installed Packages")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Ecosystem")
    table.add_column("Source")

    total = 0
    filter_set = set(ecosystem) if ecosystem else None

    for collector in collectors:
        if not collector.is_available():
            continue
        packages = collector.collect()
        for pkg in packages:
            if filter_set and pkg.ecosystem not in filter_set:
                continue
            table.add_row(pkg.name, pkg.version, pkg.ecosystem, pkg.source)
            total += 1

    console.print(table)
    console.print(f"\n[bold]Total: {total} packages[/bold]")


@main.command()
@click.option("--apply", is_flag=True, help="Actually run update commands (default is dry-run)")
@click.option("--dry-run", is_flag=True, default=False, help="Show what would be updated (default behavior)")
@click.option("--skip-reboot", is_flag=True, help="Skip updates that require a reboot")
@click.option(
    "--ecosystem",
    multiple=True,
    help="Filter to specific ecosystem (deb, snap, flatpak, pypi, npm, cargo, brew)",
)
@click.option("--livepatch", is_flag=True, help="Use kernel livepatch instead of reboot for kernel CVEs")
def fix(apply: bool, dry_run: bool, skip_reboot: bool, ecosystem: tuple[str, ...], livepatch: bool) -> None:
    """Auto-remediate vulnerabilities by updating packages."""
    from vulnscope.remediate import (
        apply_remediations,
        build_livepatch_remediations,
        build_remediations,
        print_remediation_table,
        print_results_table,
    )

    raw_config = load_config()
    config = build_scan_config(raw_config)

    from vulnscope.scanner import run_scan

    click.echo("Scanning for fixable vulnerabilities...")
    try:
        result = asyncio.run(run_scan(config))
    except KeyboardInterrupt:
        click.echo("\nScan cancelled.", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Scan error: {e}", err=True)
        sys.exit(2)

    remediations = build_remediations(result)

    if livepatch:
        from vulnscope.inventory.livepatch import detect_livepatch

        lp_status = detect_livepatch()
        if not lp_status.available:
            click.echo("No livepatch system detected (canonical-livepatch or kpatch).", err=True)
        elif not lp_status.enabled:
            click.echo(f"Livepatch ({lp_status.backend}) is installed but not enabled.", err=True)
        else:
            click.echo(f"Livepatch ({lp_status.backend}) detected — using for kernel CVEs.")
            lp_rems = build_livepatch_remediations(result, livepatch_status=lp_status)
            if lp_rems:
                lp_packages = {r.package for r in lp_rems}
                remediations = [r for r in remediations if r.package not in lp_packages]
                remediations.extend(lp_rems)

    if ecosystem:
        eco_set = set(ecosystem)
        remediations = [r for r in remediations if r.ecosystem in eco_set]

    if skip_reboot:
        remediations = [r for r in remediations if not r.requires_reboot]

    if not apply:
        print_remediation_table(remediations, dry_run=True)
        if remediations:
            click.echo("\nRun with --apply to execute these updates.")
        sys.exit(0)

    print_remediation_table(remediations, dry_run=False)
    if not remediations:
        sys.exit(0)

    results = apply_remediations(remediations)
    print_results_table(results)

    failures = [r for r in results if not r.success]
    if failures:
        sys.exit(1)
    sys.exit(0)


@main.group()
def cache() -> None:
    """Manage local vulnerability cache."""


@cache.command("clear")
def cache_clear() -> None:
    """Clear the local vulnerability cache."""
    from vulnscope.config import CACHE_DB
    if CACHE_DB.exists():
        CACHE_DB.unlink()
        click.echo(f"Cache cleared: {CACHE_DB}")
    else:
        click.echo("Cache is already empty.")


@cache.command("info")
def cache_info() -> None:
    """Show cache location and size."""
    import os as _os

    from vulnscope.config import CACHE_DB
    if CACHE_DB.exists():
        size = _os.path.getsize(CACHE_DB)
        click.echo(f"Cache location: {CACHE_DB}")
        click.echo(f"Cache size: {size / 1024:.1f} KB")
    else:
        click.echo(f"Cache location: {CACHE_DB} (not yet created)")


@main.group()
def watch() -> None:
    """Background watch mode — periodic scans with desktop notifications."""


def _pid_file():
    from vulnscope.scan_store import DATA_DIR
    return DATA_DIR / "watch.pid"


def _read_pid() -> int | None:
    pf = _pid_file()
    if not pf.exists():
        return None
    try:
        pid = int(pf.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        pf.unlink(missing_ok=True)
        return None


@watch.command("start")
@click.option("--interval", default=360, type=int, help="Scan interval in minutes (default: 360 = 6 hours)")
@click.option("--foreground", is_flag=True, help="Run in foreground instead of daemonizing")
@click.option("--auto-fix", is_flag=True, help="Automatically remediate new vulnerabilities (skip reboot-requiring updates)")
@click.option("--notify-command", default=None, type=str, help="Custom notification command (receives title and body as arguments)")
def watch_start(interval: int, foreground: bool, auto_fix: bool, notify_command: str | None) -> None:
    """Start periodic background scanning."""
    existing = _read_pid()
    if existing:
        click.echo(f"Watch daemon already running (PID {existing}). Use 'vulnscope watch stop' first.")
        sys.exit(1)

    if not foreground:
        try:
            pid = os.fork()
        except OSError as exc:
            click.echo(f"Failed to daemonize: {exc}", err=True)
            sys.exit(1)
        if pid > 0:
            msg = f"Watch daemon started (PID {pid}), scanning every {interval} minutes."
            if auto_fix:
                msg += " Auto-fix enabled."
            click.echo(msg)
            return
        os.setsid()
        sys.stdin = open(os.devnull)
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

    pf = _pid_file()
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(str(os.getpid()))

    def _cleanup(*_args):
        pf.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    try:
        _watch_loop(interval, auto_fix=auto_fix, notify_command=notify_command)
    finally:
        pf.unlink(missing_ok=True)


def _watch_loop(interval_minutes: int, *, auto_fix: bool = False, notify_command: str | None = None) -> None:
    from vulnscope.notify import send_notification
    from vulnscope.scan_store import DATA_DIR, diff_scans, load_latest_scan, save_scan
    from vulnscope.scanner import run_scan

    raw_config = load_config()
    config = build_scan_config(raw_config)

    while True:
        previous = load_latest_scan()
        try:
            result = asyncio.run(run_scan(config))
        except Exception:
            time.sleep(interval_minutes * 60)
            continue

        save_scan(result)

        if previous:
            new_vulns = diff_scans(previous, result)
            if new_vulns:
                send_notification(new_vulns, custom_command=notify_command)

                if auto_fix:
                    _auto_fix_vulns(result, DATA_DIR, notify_command=notify_command)

        time.sleep(interval_minutes * 60)


def _auto_fix_vulns(result: object, data_dir: object, *, notify_command: str | None = None) -> None:
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    from vulnscope.notify import send_fix_notification
    from vulnscope.remediate import apply_remediations, build_remediations

    remediations = build_remediations(result)  # type: ignore[arg-type]
    remediations = [r for r in remediations if not r.requires_reboot]

    if not remediations:
        return

    results = apply_remediations(remediations)

    log_dir = Path(str(data_dir)) / "autofix_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    succeeded = sum(1 for r in results if r.success)
    failed = sum(1 for r in results if not r.success)
    log_entry = {
        "timestamp": ts,
        "remediations_attempted": len(results),
        "succeeded": succeeded,
        "failed": failed,
        "details": [
            {
                "package": r.remediation.package,
                "ecosystem": r.remediation.ecosystem,
                "fixed_version": r.remediation.fixed_version,
                "success": r.success,
                "output": r.output[:200],
            }
            for r in results
        ],
    }

    log_file = log_dir / f"autofix_{ts}.json"
    log_file.write_text(json.dumps(log_entry, indent=2))

    send_fix_notification(succeeded, failed, custom_command=notify_command)


@watch.command("install-service")
@click.option("--start", is_flag=True, help="Also start the service immediately")
def watch_install_service(start: bool) -> None:
    """Install a systemd user service (or launchd plist on macOS)."""
    from vulnscope.service import install_service

    try:
        msg = install_service(start=start)
        click.echo(msg)
    except subprocess.CalledProcessError as exc:
        click.echo(f"Failed to install service: {exc}", err=True)
        sys.exit(1)


@watch.command("uninstall-service")
def watch_uninstall_service() -> None:
    """Remove the systemd user service (or launchd plist on macOS)."""
    from vulnscope.service import uninstall_service

    msg = uninstall_service()
    click.echo(msg)


@watch.command("stop")
def watch_stop() -> None:
    """Stop the watch daemon."""
    pid = _read_pid()
    if not pid:
        click.echo("No watch daemon is running.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Watch daemon (PID {pid}) stopped.")
    except ProcessLookupError:
        click.echo("Watch daemon process not found (stale PID file removed).")
    _pid_file().unlink(missing_ok=True)


@watch.command("status")
def watch_status() -> None:
    """Check if the watch daemon is running."""
    pid = _read_pid()
    if pid:
        click.echo(f"Watch daemon is running (PID {pid}).")
    else:
        click.echo("Watch daemon is not running.")
