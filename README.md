# VulnScope

CLI vulnerability scanner for Linux systems. Inventories your OS, kernel, and all installed packages, then queries [OSV.dev](https://osv.dev), [NVD](https://nvd.nist.gov), and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to surface every known CVE.

Results are shown in a rich interactive Textual TUI — or piped as JSON/CSV/SARIF for CI integration.

---

## Features

- **Multi-ecosystem inventory**: dpkg, rpm, apk, pip, npm, cargo, docker
- **Vulnerability sources**: OSV.dev (primary), NVD API 2.0, CISA Known Exploited Vulnerabilities
- **Interactive TUI**: filterable/searchable/sortable table with detail panel
- **CI-friendly**: `--json`, `--csv`, `--sarif`, `--html` output modes; exit code 1 on findings
- **Local SQLite cache**: 24h TTL to avoid hammering APIs on repeated scans
- **CISA KEV highlighting**: instantly see which vulns are actively exploited in the wild

---

## Installation

```bash
# Recommended: pipx (isolated install)
pipx install vulnscope

# Or: pip
pip install vulnscope

# Or: clone + editable install
git clone https://github.com/michaelsc44/vulnscope.git
cd vulnscope
pip install -e .
```

---

## Usage

```bash
# Full interactive TUI scan
vulnscope

# Non-interactive table output
vulnscope scan --no-ui

# Filter by severity
vulnscope scan --no-ui --severity high

# Machine-readable output
vulnscope scan --json | jq '.vulnerabilities[] | select(.severity == "critical")'
vulnscope scan --csv > report.csv
vulnscope scan --sarif > results.sarif     # GitHub Advanced Security compatible
vulnscope scan --html report.html

# Inventory only (no vuln lookup)
vulnscope inventory

# Cache management
vulnscope cache clear
vulnscope cache info
```

### CI / GitHub Actions

```yaml
- name: Scan for vulnerabilities
  run: |
    pip install vulnscope
    vulnscope scan --sarif > results.sarif
  # exits 1 if vulnerabilities found

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Configuration

Create `~/.config/vulnscope/config.toml`:

```toml
[nvd]
api_key = ""           # Optional — free key at https://nvd.nist.gov/developers/request-an-api-key
                       # Raises rate limit from 5/30s to 50/30s

[scan]
ecosystems = ["os", "deb", "rpm", "pypi", "npm", "cargo", "apk"]
skip = []              # Ecosystems to skip
docker_contents = false

[cache]
ttl_hours = 24         # Cache TTL in hours
```

Or via environment variable:
```bash
export NVD_API_KEY=your-key-here
```

---

## Architecture

```
vulnscope/
├── cli.py              # Click CLI entry point
├── scanner.py          # Async pipeline orchestrator
├── matcher.py          # Version comparison (semver, deb, rpm)
├── models.py           # Dataclasses: InstalledPackage, Vulnerability, ScanResult
├── config.py           # Config loading, platformdirs paths
├── inventory/          # System package collectors
│   ├── os_info.py      # /etc/os-release + uname
│   ├── dpkg.py         # Debian/Ubuntu
│   ├── rpm.py          # RHEL/Fedora/SUSE
│   ├── apk.py          # Alpine
│   ├── pip_packages.py # Python packages
│   ├── npm_packages.py # Node.js global
│   ├── cargo_packages.py # Rust crates
│   └── docker_images.py  # Docker images
├── databases/          # Vulnerability data sources
│   ├── osv.py          # OSV.dev batch API
│   ├── nvd.py          # NVD API 2.0 + CPE queries
│   ├── kev.py          # CISA KEV catalog
│   └── cache.py        # SQLite cache
├── ui/
│   ├── app.py          # Textual interactive TUI
│   ├── tables.py       # Rich non-interactive table
│   └── detail_view.py  # CVE detail panel
└── export/
    ├── json_export.py
    ├── csv_export.py
    ├── sarif_export.py  # SARIF 2.1.0
    └── html_export.py
```

---

## Development

```bash
git clone https://github.com/michaelsc44/vulnscope.git
cd vulnscope
pip install -e ".[dev]"
pytest tests/ -v
ruff check vulnscope tests
```

---

## License

MIT — see [LICENSE](LICENSE)
