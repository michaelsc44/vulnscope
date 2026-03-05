from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from vulnscope import __version__
from vulnscope.models import ScanResult, Severity, Vulnerability
from vulnscope.ui.detail_view import VulnDetailPanel

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]


class SummaryBar(Static):
    DEFAULT_CSS = """
    SummaryBar {
        height: 3;
        padding: 0 2;
        background: $surface;
        border-bottom: solid $primary;
    }
    """

    def __init__(self, result: ScanResult, **kwargs):
        super().__init__(**kwargs)
        self._result = result

    def render(self) -> str:
        os_info = self._result.os_info
        os_str = f"{os_info.get('pretty_name', 'Linux')} / kernel {os_info.get('kernel_version', '?')}"
        counts = self._result.counts_by_severity
        parts = []
        for sev in SEVERITY_ORDER:
            count = counts.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                parts.append(f"[{color}]{sev.value.upper()}: {count}[/{color}]")
        sev_str = "  |  ".join(parts) if parts else "No vulnerabilities"
        return f"[dim]{os_str}[/dim]\n{sev_str}  |  Risk Score: [bold]{self._result.risk_score}/100[/bold]"


class VulnScopeApp(App):
    TITLE = f"VulnScope v{__version__}"
    CSS = """
    Screen {
        layout: vertical;
    }
    #main-container {
        height: 1fr;
        layout: vertical;
    }
    #filter-bar {
        height: 3;
        layout: horizontal;
        padding: 0 2;
        background: $surface-darken-1;
    }
    #filter-bar Label {
        margin-right: 1;
        height: 3;
        content-align: left middle;
    }
    #search-input {
        width: 30;
        height: 3;
    }
    #vuln-table {
        height: 1fr;
    }
    VulnDetailPanel {
        height: 12;
        dock: bottom;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("/", "focus_search", "Search"),
        Binding("escape", "clear_search", "Clear search"),
        Binding("f", "cycle_filter", "Filter severity"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("c", "copy_fix", "Copy fix"),
        Binding("e", "export_menu", "Export"),
        Binding("enter", "toggle_detail", "Toggle detail"),
    ]

    _search_query: reactive[str] = reactive("")
    _severity_filter: reactive[str] = reactive("all")
    _sort_mode: reactive[str] = reactive("severity")
    _filter_cycle = ["all", "critical", "high", "medium", "low"]
    _sort_cycle = ["severity", "cvss", "name"]

    def __init__(self, result: ScanResult, **kwargs):
        super().__init__(**kwargs)
        self._result = result
        self._all_vulns = list(result.vulnerabilities)
        self._filtered_vulns: list[Vulnerability] = []
        self._selected_idx: int = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield SummaryBar(self._result)
        with Container(id="main-container"):
            with Horizontal(id="filter-bar"):
                yield Label(f"Filter: [{self._severity_filter}]", id="filter-label")
                yield Label(f"Sort: [{self._sort_mode}]", id="sort-label")
                yield Input(placeholder="/search...", id="search-input")
            yield DataTable(id="vuln-table", zebra_stripes=True, cursor_type="row")
        yield VulnDetailPanel(id="detail-panel")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("CVE ID", "Package", "Installed", "Fixed", "Severity", "CVSS", "KEV")
        self._refresh_table()

    def _apply_filters(self) -> list[Vulnerability]:
        vulns = list(self._all_vulns)

        if self._search_query:
            q = self._search_query.lower()
            vulns = [
                v for v in vulns
                if q in v.cve_id.lower()
                or q in v.affected_package.name.lower()
                or q in v.title.lower()
            ]

        if self._severity_filter != "all":
            vulns = [v for v in vulns if v.severity.value == self._severity_filter]

        if self._sort_mode == "severity":
            sev_order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
            vulns.sort(key=lambda v: (
                sev_order.get(v.severity, 99),
                0 if v.is_known_exploited else 1,
                -(v.cvss_score or 0),
            ))
        elif self._sort_mode == "cvss":
            vulns.sort(key=lambda v: -(v.cvss_score or 0))
        elif self._sort_mode == "name":
            vulns.sort(key=lambda v: v.affected_package.name.lower())

        return vulns

    def _refresh_table(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        self._filtered_vulns = self._apply_filters()

        for v in self._filtered_vulns:
            color = SEVERITY_COLORS.get(v.severity, "white")
            kev = "⚠" if v.is_known_exploited else ""
            cvss = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "N/A"
            fixed = v.fixed_version or "—"
            table.add_row(
                v.cve_id,
                v.affected_package.name,
                v.affected_package.version,
                fixed,
                f"[{color}]{v.severity.value.upper()}[/{color}]",
                cvss,
                f"[red]{kev}[/red]" if kev else "",
            )

        self._update_detail()
        self._update_filter_labels()

    def _update_detail(self) -> None:
        panel = self.query_one(VulnDetailPanel)
        if self._filtered_vulns and 0 <= self._selected_idx < len(self._filtered_vulns):
            panel.set_vuln(self._filtered_vulns[self._selected_idx])
        else:
            panel.set_vuln(None)

    def _update_filter_labels(self) -> None:
        try:
            self.query_one("#filter-label", Label).update(f"Filter: [{self._severity_filter}]")
            self.query_one("#sort-label", Label).update(f"Sort: [{self._sort_mode}]")
        except Exception:
            pass

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._selected_idx = event.cursor_row
        self._update_detail()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._search_query = event.value
        self._refresh_table()

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_clear_search(self) -> None:
        inp = self.query_one("#search-input", Input)
        inp.value = ""
        self._search_query = ""
        self._refresh_table()
        self.query_one(DataTable).focus()

    def action_cycle_filter(self) -> None:
        idx = self._filter_cycle.index(self._severity_filter)
        self._severity_filter = self._filter_cycle[(idx + 1) % len(self._filter_cycle)]
        self._selected_idx = 0
        self._refresh_table()

    def action_cycle_sort(self) -> None:
        idx = self._sort_cycle.index(self._sort_mode)
        self._sort_mode = self._sort_cycle[(idx + 1) % len(self._sort_cycle)]
        self._refresh_table()

    def action_copy_fix(self) -> None:
        panel = self.query_one(VulnDetailPanel)
        fix_cmd = panel.get_fix_command()
        if fix_cmd:
            try:
                import pyperclip  # type: ignore[import-untyped]
                pyperclip.copy(fix_cmd)
                self.notify(f"Copied: {fix_cmd}", title="Copied to clipboard")
            except Exception:
                self.notify(fix_cmd, title="Fix command (pyperclip unavailable)")

    def action_export_menu(self) -> None:
        self.notify("Use --json, --csv, --sarif, or --html flags for export", title="Export")

    def action_toggle_detail(self) -> None:
        panel = self.query_one(VulnDetailPanel)
        panel.toggle()
