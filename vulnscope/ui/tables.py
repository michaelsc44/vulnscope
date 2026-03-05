from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from vulnscope.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]


def _sev_text(sev: Severity) -> Text:
    labels = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.UNKNOWN: "UNKNOWN",
    }
    return Text(labels[sev], style=SEVERITY_COLORS[sev])


def print_results(
    result: ScanResult,
    severity_filter: str | None = None,
    console: Console | None = None,
) -> None:
    if console is None:
        console = Console()

    os_info = result.os_info
    os_str = f"{os_info.get('pretty_name', 'Linux')} / kernel {os_info.get('kernel_version', 'unknown')}"
    counts = result.counts_by_severity

    console.print()
    console.print(f"[bold blue]VulnScope[/bold blue]  {os_str}")
    console.print()

    # Severity summary
    summary_parts = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{sev.value.upper()}: {count}[/{color}]")
    if summary_parts:
        console.print("  " + "  |  ".join(summary_parts) + f"  |  Risk Score: {result.risk_score}/100")
    console.print(f"  Scanned {result.total_packages} packages in {result.scan_duration_seconds:.1f}s")
    console.print()

    vulns = result.vulnerabilities
    if not vulns:
        console.print("[green bold]No vulnerabilities found.[/green bold]")
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        expand=True,
    )
    table.add_column("CVE ID", style="bold", min_width=18)
    table.add_column("Package", min_width=14)
    table.add_column("Installed", min_width=12)
    table.add_column("Fixed", min_width=12)
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("CVSS", justify="right", min_width=5)
    table.add_column("KEV", justify="center", min_width=4)

    for v in vulns:
        kev = "[bold red]![/bold red]" if v.is_known_exploited else ""
        cvss = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "N/A"
        fixed = v.fixed_version or "—"
        table.add_row(
            v.cve_id,
            v.affected_package.name,
            v.affected_package.version,
            fixed,
            _sev_text(v.severity),
            cvss,
            kev,
        )

    console.print(table)
    console.print()
    console.print(f"[dim]Total: {len(vulns)} vulnerabilities[/dim]")
