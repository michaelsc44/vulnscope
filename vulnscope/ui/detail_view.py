from textual.widget import Widget

from vulnscope.models import Severity, Vulnerability

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}


def _fix_command(vuln: Vulnerability) -> str | None:
    pkg = vuln.affected_package
    fixed = vuln.fixed_version
    if not fixed:
        return None
    eco = pkg.ecosystem
    if eco == "deb":
        return f"sudo apt install {pkg.name}={fixed}"
    if eco == "rpm":
        return f"sudo dnf update {pkg.name}"
    if eco == "pypi":
        return f"pip install '{pkg.name}>={fixed}'"
    if eco == "npm":
        return f"npm install -g {pkg.name}@{fixed}"
    if eco == "cargo":
        return f"cargo install {pkg.name} --version {fixed}"
    if eco == "apk":
        return f"apk upgrade {pkg.name}"
    return None


class VulnDetailPanel(Widget):
    DEFAULT_CSS = """
    VulnDetailPanel {
        height: 12;
        border: solid $accent;
        padding: 1 2;
        background: $surface;
    }
    """

    def __init__(self, vuln: Vulnerability | None = None, **kwargs):
        super().__init__(**kwargs)
        self._vuln = vuln

    def set_vuln(self, vuln: Vulnerability | None) -> None:
        self._vuln = vuln
        self.refresh()

    def render(self) -> str:
        if self._vuln is None:
            return "[dim]Select a vulnerability to see details[/dim]"
        v = self._vuln
        color = SEVERITY_COLORS.get(v.severity, "white")
        kev_str = " [bold red]⚠ In CISA KEV[/bold red]" if v.is_known_exploited else ""
        cvss_str = f"CVSS: [bold]{v.cvss_score:.1f}[/bold]" if v.cvss_score is not None else ""
        kev_due = f" (due {v.kev_due_date})" if v.kev_due_date else ""

        lines = [
            f"[bold {color}]▸ {v.cve_id}[/bold {color}] — {v.title}  {cvss_str}{kev_str}{kev_due}",
        ]

        if v.description:
            desc = v.description[:300]
            if len(v.description) > 300:
                desc += "..."
            lines.append(f"  {desc}")

        fix_cmd = _fix_command(v)
        if fix_cmd:
            lines.append(f"  [dim]Fix:[/dim] [cyan]{fix_cmd}[/cyan]")
        elif not v.fixed_version:
            lines.append("  [dim]No fix available[/dim]")

        if v.references:
            lines.append(f"  [dim]Refs:[/dim] {v.references[0]}")

        if v.cwe_ids:
            lines.append(f"  [dim]CWE:[/dim] {', '.join(v.cwe_ids)}")

        return "\n".join(lines)

    def get_fix_command(self) -> str | None:
        if self._vuln:
            return _fix_command(self._vuln)
        return None
