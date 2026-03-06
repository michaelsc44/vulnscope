from collections import defaultdict

from rich import box
from rich.console import Console
from rich.panel import Panel
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


def print_summary(
    result: ScanResult,
    console: Console | None = None,
) -> None:
    if console is None:
        console = Console()

    vulns = result.vulnerabilities
    os_info = result.os_info
    os_str = f"{os_info.get('pretty_name', 'Linux')} / kernel {os_info.get('kernel_version', 'unknown')}"
    counts = result.counts_by_severity

    console.print()
    console.print(f"[bold blue]VulnScope Summary[/bold blue]  {os_str}")
    console.print(f"  Scanned {result.total_packages} packages in {result.scan_duration_seconds:.1f}s")
    console.print()

    if not vulns:
        console.print("[green bold]No vulnerabilities found.[/green bold]")
        return

    # 1) Risk breakdown by severity
    sev_table = Table(title="Risk Breakdown", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    sev_table.add_column("Severity", min_width=10)
    sev_table.add_column("Count", justify="right", min_width=6)
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count > 0:
            sev_table.add_row(Text(sev.value.upper(), style=SEVERITY_COLORS[sev]), str(count))
    sev_table.add_row(Text("TOTAL", style="bold"), str(len(vulns)))
    console.print(sev_table)
    console.print(f"  Risk Score: [bold]{result.risk_score}/100[/bold]")
    console.print()

    # 2) Top 5 most vulnerable packages
    pkg_vuln_count: dict[str, int] = defaultdict(int)
    for v in vulns:
        pkg_vuln_count[v.affected_package.name] += 1
    top_pkgs = sorted(pkg_vuln_count.items(), key=lambda x: x[1], reverse=True)[:5]

    top_table = Table(title="Top 5 Most Vulnerable Packages", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    top_table.add_column("Package", min_width=20)
    top_table.add_column("CVEs", justify="right", min_width=6)
    for name, count in top_pkgs:
        top_table.add_row(name, str(count))
    console.print(top_table)
    console.print()

    # 3) KEV - packages with known exploited vulnerabilities
    kev_vulns = [v for v in vulns if v.is_known_exploited]
    if kev_vulns:
        kev_table = Table(title="Known Exploited Vulnerabilities (KEV)", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
        kev_table.add_column("CVE ID", min_width=18)
        kev_table.add_column("Package", min_width=14)
        kev_table.add_column("Severity", min_width=10)
        kev_table.add_column("Due Date", min_width=12)
        for v in kev_vulns:
            kev_table.add_row(
                v.cve_id,
                v.affected_package.name,
                _sev_text(v.severity),
                v.kev_due_date or "—",
            )
        console.print(kev_table)
        console.print()

    # 4) Actionable - packages with available fixes
    fixable = [v for v in vulns if v.fixed_version is not None]
    if fixable:
        # Group by ecosystem for update commands
        by_ecosystem: dict[str, list[tuple[str, str]]] = defaultdict(list)
        seen: set[tuple[str, str]] = set()
        for v in fixable:
            key = (v.affected_package.name, v.fixed_version)
            if key not in seen:
                seen.add(key)
                by_ecosystem[v.affected_package.ecosystem].append(key)

        update_cmds = {
            "deb": lambda name, ver: f"apt install {name}={ver}",
            "rpm": lambda name, ver: f"dnf update {name}-{ver}",
            "apk": lambda name, ver: f"apk upgrade {name}",
            "pypi": lambda name, ver: f"pip install {name}>={ver}",
            "npm": lambda name, ver: f"npm install {name}@{ver}",
            "cargo": lambda name, ver: f"cargo update -p {name}",
            "snap": lambda name, ver: f"snap refresh {name}",
        }

        act_table = Table(title="Actionable - Updates Available", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
        act_table.add_column("Package", min_width=14)
        act_table.add_column("Fixed Version", min_width=12)
        act_table.add_column("Update Command", min_width=30)
        for eco, pkgs in by_ecosystem.items():
            cmd_fn = update_cmds.get(eco, lambda name, ver: f"# update {name} to {ver}")
            for name, ver in pkgs:
                act_table.add_row(name, ver, f"[dim]{cmd_fn(name, ver)}[/dim]")
        console.print(act_table)
        console.print(f"  [bold]{len(seen)}[/bold] packages can be updated to fix [bold]{len(fixable)}[/bold] vulnerabilities")
    else:
        console.print("[dim]No fixes currently available.[/dim]")
    console.print()
