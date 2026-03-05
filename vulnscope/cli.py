import asyncio
import sys

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

    non_interactive = no_ui or output_json or output_csv or sarif or bool(html_file)

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
    elif non_interactive:
        from vulnscope.ui.tables import print_results
        print_results(result, severity_filter=severity)
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
    from vulnscope.inventory.cargo_packages import CargoCollector
    from vulnscope.inventory.dpkg import DpkgCollector
    from vulnscope.inventory.npm_packages import NpmCollector
    from vulnscope.inventory.os_info import get_os_info
    from vulnscope.inventory.pip_packages import PipCollector
    from vulnscope.inventory.rpm import RpmCollector

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
    import os

    from vulnscope.config import CACHE_DB
    if CACHE_DB.exists():
        size = os.path.getsize(CACHE_DB)
        click.echo(f"Cache location: {CACHE_DB}")
        click.echo(f"Cache size: {size / 1024:.1f} KB")
    else:
        click.echo(f"Cache location: {CACHE_DB} (not yet created)")
