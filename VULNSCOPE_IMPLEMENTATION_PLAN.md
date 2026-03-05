# VulnScope — Implementation Plan

An open-source, installable CLI tool that inventories a machine's OS, kernel, and all installed packages, then queries public vulnerability databases (NVD, CISA KEV, OSV) to surface every known CVE present on the system. Results are displayed in a rich interactive terminal UI.

---

## 1. Language & Distribution

**Language:** Python 3.10+

**Rationale:** Native access to system package managers via subprocess, excellent HTTP libraries, `rich`/`textual` for terminal UI, and trivial `pipx install` distribution. No compilation step means users can also just `git clone` and run.

**Install methods to support:**

```bash
# Primary: pipx (isolated install)
pipx install vulnscope

# Alt: pip
pip install vulnscope

# Alt: clone + run
git clone https://github.com/<org>/vulnscope.git
cd vulnscope
pip install -e .
```

**Entry point:** `vulnscope` CLI command via pyproject.toml `[project.scripts]`.

---

## 2. Project Structure

```
vulnscope/
├── pyproject.toml              # Build config, dependencies, entry point
├── README.md
├── LICENSE                     # MIT
├── vulnscope/
│   ├── __init__.py             # Version string
│   ├── cli.py                  # CLI entry point (click or argparse)
│   ├── config.py               # User config, cache paths, API keys
│   ├── scanner.py              # Top-level orchestrator
│   │
│   ├── inventory/              # System inventory collectors
│   │   ├── __init__.py
│   │   ├── base.py             # Abstract base class for collectors
│   │   ├── os_info.py          # OS name, version, kernel
│   │   ├── dpkg.py             # Debian/Ubuntu (dpkg)
│   │   ├── rpm.py              # RHEL/Fedora/SUSE (rpm)
│   │   ├── apk.py              # Alpine (apk)
│   │   ├── pacman.py           # Arch (pacman)
│   │   ├── brew.py             # macOS Homebrew
│   │   ├── pip_packages.py     # Python packages (all venvs + system)
│   │   ├── npm_packages.py     # Node.js global + project-local
│   │   ├── gem_packages.py     # Ruby gems
│   │   ├── cargo_packages.py   # Rust crates (cargo)
│   │   ├── go_packages.py      # Go modules
│   │   └── docker_images.py    # Docker image layers (if docker available)
│   │
│   ├── databases/              # Vulnerability database query layer
│   │   ├── __init__.py
│   │   ├── base.py             # Abstract base for DB sources
│   │   ├── osv.py              # OSV.dev API (primary — covers all ecosystems)
│   │   ├── nvd.py              # NVD API 2.0
│   │   ├── kev.py              # CISA Known Exploited Vulnerabilities catalog
│   │   └── cache.py            # Local SQLite cache with TTL
│   │
│   ├── matcher.py              # Version comparison + CPE matching logic
│   ├── models.py               # Dataclasses: Package, Vulnerability, ScanResult
│   │
│   ├── ui/                     # Terminal UI
│   │   ├── __init__.py
│   │   ├── app.py              # Textual app (interactive mode)
│   │   ├── tables.py           # Rich table formatters (non-interactive)
│   │   └── detail_view.py      # Expanded CVE detail panel
│   │
│   └── export/                 # Output formats
│       ├── __init__.py
│       ├── json_export.py
│       ├── csv_export.py
│       ├── sarif_export.py     # SARIF for CI/CD integration
│       └── html_export.py      # Standalone HTML report
│
└── tests/
    ├── test_inventory.py
    ├── test_matcher.py
    ├── test_databases.py
    └── fixtures/               # Sample dpkg output, mock API responses, etc.
```

---

## 3. Core Dependencies

```toml
[project]
name = "vulnscope"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "httpx>=0.27",          # Async HTTP client for API calls
    "textual>=0.80",        # Interactive terminal UI framework
    "rich>=13.0",           # Rich terminal output (tables, progress, etc.)
    "click>=8.1",           # CLI framework
    "packaging>=24.0",      # PEP 440 version parsing and comparison
    "platformdirs>=4.0",    # XDG-compliant cache/config directories
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "respx"]  # respx for mocking httpx

[project.scripts]
vulnscope = "vulnscope.cli:main"
```

---

## 4. Inventory Collectors — Detailed Design

### 4.1 Base Interface

```python
# vulnscope/inventory/base.py
from dataclasses import dataclass

@dataclass
class InstalledPackage:
    name: str
    version: str
    ecosystem: str          # "deb", "rpm", "pypi", "npm", "gem", "cargo", "go", "apk", "docker"
    source: str             # e.g. "dpkg", "pip3", "npm-global"
    arch: str | None        # "amd64", "arm64", etc.
    purl: str               # Package URL (pkg:deb/ubuntu/openssl@3.0.2)

class BaseCollector:
    """Each collector detects if it's relevant, then yields InstalledPackage."""
    def is_available(self) -> bool: ...
    def collect(self) -> list[InstalledPackage]: ...
```

### 4.2 OS & Kernel Info (`os_info.py`)

- Parse `/etc/os-release` for distro name, version, codename, ID (ubuntu, debian, fedora, etc.)
- `uname -r` for kernel version
- On macOS: `sw_vers` for ProductName, ProductVersion, BuildVersion
- Store as a special `OSInfo` dataclass that feeds into NVD CPE queries

### 4.3 System Package Managers

**dpkg (Debian/Ubuntu):**
- Run: `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'`
- Filter to status `install ok installed`
- Parse version with `packaging.version` or dpkg-specific epoch handling
- Generate PURL: `pkg:deb/{distro}/{name}@{version}?arch={arch}`

**rpm (RHEL/Fedora/SUSE):**
- Run: `rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`
- Generate PURL: `pkg:rpm/{distro}/{name}@{version}?arch={arch}`

**apk (Alpine):**
- Run: `apk list --installed`
- Parse: `{name}-{version} {arch} {status}`

**pacman (Arch):**
- Run: `pacman -Q`
- Parse: `{name} {version}`

**Homebrew (macOS):**
- Run: `brew list --versions`
- Also: `brew list --cask --versions` for cask packages

### 4.4 Language Package Managers

**Python (pip):**
- Discover Python interpreters: `which python3`, `which python`, check common venv locations
- For each: run `{python} -m pip list --format=json`
- Also parse `~/.local/lib/python*/site-packages` for user-installed
- PURL: `pkg:pypi/{name}@{version}`

**Node.js (npm):**
- Global: `npm list -g --json --depth=0`
- Project-local: Find `package-lock.json` files under common dirs (`~/`, `~/projects/`, etc.), parse them for resolved versions. Limit search depth to avoid crawling the entire filesystem.
- PURL: `pkg:npm/{name}@{version}`

**Ruby (gem):**
- Run: `gem list --local`
- PURL: `pkg:gem/{name}@{version}`

**Rust (cargo):**
- Parse `~/.cargo/.package-cache` or run `cargo install --list`
- For project deps: find `Cargo.lock` files, parse `[[package]]` entries
- PURL: `pkg:cargo/{name}@{version}`

**Go:**
- Run: `go version -m $(which <binary>)` for installed binaries
- Parse `go.sum` files found in projects
- PURL: `pkg:golang/{module}@{version}`

### 4.5 Docker Images (optional)

- Check if `docker` is available
- Run: `docker image ls --format json`
- For each image, run: `docker inspect {image}` to get layer info
- Optionally run `docker run --rm {image} dpkg -l` or equivalent to get packages inside the image (expensive, behind a `--scan-docker-contents` flag)

---

## 5. Vulnerability Database Layer — Detailed Design

### 5.1 OSV.dev API (Primary Source)

The OSV API is the **primary query source** because it covers all ecosystems natively and accepts Package URLs directly.

**Endpoint:** `POST https://api.osv.dev/v1/query`

```json
{
  "package": {
    "purl": "pkg:pypi/requests@2.31.0"
  }
}
```

**Batch endpoint:** `POST https://api.osv.dev/v1/querybatch` — send up to 1000 packages per request. This is critical for performance.

**Implementation:**
- Batch all packages into groups of 1000
- Send concurrent batch requests via `httpx.AsyncClient`
- Parse response: each query returns a list of vulns with ID, summary, severity (CVSS), affected version ranges, references, and aliases (maps OSV IDs → CVE IDs)
- Rate limit: OSV is free and generous but add backoff just in case

### 5.2 NVD API 2.0 (Enrichment)

Used to enrich CVEs found via OSV with additional detail (CVSS vectors, CWE, references) and to query OS/kernel-level CVEs via CPE matching.

**Endpoints:**
- `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}` — single CVE lookup
- `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={CPE}` — CPE-based search

**CPE construction for OS-level queries:**
- From OS info, build CPE 2.3 strings like: `cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*`
- For the kernel: `cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*`

**Implementation:**
- NVD rate limit: 5 requests/30s without API key, 50/30s with key. Support an optional `NVD_API_KEY` env var.
- Use NVD primarily for: (a) OS/kernel CVEs that OSV doesn't cover well, (b) enriching severity/CVSS data on CVEs found via OSV
- Parse CVSS v3.1 vector strings, extract base score, severity, attack vector, etc.

### 5.3 CISA KEV Catalog (Exploit Intelligence)

The Known Exploited Vulnerabilities catalog flags CVEs that are actively exploited in the wild. This is a critical prioritization signal.

**Endpoint:** `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Implementation:**
- Download the full catalog (it's a single JSON file, ~1MB)
- Cache locally with 24h TTL
- After matching CVEs from OSV/NVD, cross-reference against KEV to flag `is_known_exploited: true`
- Include KEV-specific fields: `date_added`, `due_date`, `required_action`

### 5.4 Local SQLite Cache (`cache.py`)

All API responses get cached to avoid hammering APIs on repeated scans.

**Location:** `~/.cache/vulnscope/vulndb.sqlite` (via `platformdirs`)

**Schema:**
```sql
CREATE TABLE osv_cache (
    purl TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at TIMESTAMP
);

CREATE TABLE nvd_cache (
    cve_id TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at TIMESTAMP
);

CREATE TABLE kev_cache (
    id INTEGER PRIMARY KEY,
    catalog_json TEXT,
    fetched_at TIMESTAMP
);
```

**TTL:** Default 24 hours (configurable). `--no-cache` flag to force fresh queries. `vulnscope cache clear` subcommand.

---

## 6. Version Matching Logic (`matcher.py`)

This is the most critical and error-prone component. Getting version matching wrong means false positives or missed vulnerabilities.

### 6.1 OSV Affected Ranges

OSV returns structured affected ranges. The matcher needs to handle:

```python
def is_affected(installed_version: str, affected_ranges: list[dict]) -> bool:
    """
    OSV ranges come in two flavors:
    
    1. SEMVER ranges: {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}
       - Use packaging.version.Version for comparison
    
    2. ECOSYSTEM ranges: {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.1"}]}
       - Use ecosystem-specific version comparison
    
    3. Exact versions: {"versions": ["1.0.0", "1.0.1", "1.1.0"]}
       - Direct string match
    """
```

### 6.2 Distro-Specific Version Comparison

Debian/Ubuntu versions have epochs and release suffixes (e.g., `1:2.38-1ubuntu4.2`). RPM versions have their own comparison rules. Don't try to use semver for these.

**Strategy:**
- For `pypi`, `npm`, `gem`, `cargo`, `golang` → use `packaging.version.Version` (PEP 440) or semver
- For `deb` → implement Debian version comparison (split epoch:upstream-revision, compare each segment)
- For `rpm` → implement RPM version comparison (`rpmvercmp` algorithm)
- The `packaging` library handles PEP 440. For deb/rpm, implement or use a small utility function.

### 6.3 CPE Matching for OS-Level

For NVD results that use CPE ranges, compare the installed OS/kernel version against CPE `versionStartIncluding`/`versionEndExcluding` in the NVD `configurations` node.

---

## 7. Data Models (`models.py`)

```python
from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

@dataclass
class Vulnerability:
    cve_id: str                         # "CVE-2024-6387"
    aliases: list[str]                  # ["GHSA-xxxx", "RUSTSEC-2024-..."]
    title: str                          # Short name / summary
    description: str                    # Full description
    severity: Severity
    cvss_score: float | None            # 0.0 - 10.0
    cvss_vector: str | None             # "CVSS:3.1/AV:N/AC:L/..."
    cwe_ids: list[str]                  # ["CWE-362"]
    affected_package: InstalledPackage   # The package on this machine
    fixed_version: str | None           # Version that fixes it, or None if no fix
    is_known_exploited: bool            # In CISA KEV
    kev_due_date: str | None            # KEV remediation deadline
    references: list[str]               # URLs to advisories
    published_date: str | None
    source: str                         # "osv", "nvd", etc.

@dataclass
class ScanResult:
    scan_id: str                        # UUID
    timestamp: str                      # ISO 8601
    os_info: dict                       # OS name, version, kernel
    total_packages: int
    vulnerabilities: list[Vulnerability]
    scan_duration_seconds: float

    @property
    def counts_by_severity(self) -> dict[Severity, int]: ...
    
    @property
    def risk_score(self) -> int: ...    # Weighted aggregate score
```

---

## 8. Scanner Orchestrator (`scanner.py`)

This is the main pipeline that ties everything together.

```python
async def run_scan(config: ScanConfig) -> ScanResult:
    """
    Pipeline:
    1. Collect OS info
    2. Run all applicable inventory collectors in parallel
    3. Deduplicate packages (same package from multiple sources)
    4. Batch-query OSV for all packages
    5. Query NVD for OS/kernel CPE matches
    6. Download/load CISA KEV catalog
    7. Enrich: cross-reference KEV, fetch NVD detail for critical/high CVEs
    8. Deduplicate vulnerabilities (same CVE from multiple sources)
    9. Sort by severity (critical → low), then by CVSS score
    10. Return ScanResult
    """
```

**Parallelism:**
- Inventory collectors run in parallel threads (they're subprocess-bound, not CPU-bound)
- API queries use `asyncio` with `httpx.AsyncClient` for concurrent HTTP
- OSV batch endpoint handles most work in few requests
- NVD enrichment is parallelized but respects rate limits with a semaphore

**Progress reporting:**
- Each phase reports progress via a callback or shared state object
- The UI layer subscribes to progress events to show a live progress bar

---

## 9. CLI Interface (`cli.py`)

```
vulnscope                          # Full interactive scan with TUI
vulnscope scan                     # Same as above
vulnscope scan --no-ui             # Non-interactive, prints rich table and exits
vulnscope scan --json              # JSON output to stdout
vulnscope scan --csv               # CSV output to stdout
vulnscope scan --sarif             # SARIF output (for CI/CD)
vulnscope scan --html report.html  # Generate standalone HTML report
vulnscope scan --severity high     # Only show high+ severity
vulnscope scan --ecosystem pypi    # Only scan Python packages
vulnscope scan --skip docker       # Skip Docker scanning
vulnscope scan --scan-docker-contents  # Also scan packages inside Docker images

vulnscope inventory                # Just show installed packages, no vuln lookup
vulnscope cache clear              # Clear the local vuln cache
vulnscope version                  # Print version
```

**Config file:** `~/.config/vulnscope/config.toml`
```toml
[nvd]
api_key = ""           # Optional, increases rate limit 10x

[scan]
ecosystems = ["os", "deb", "pypi", "npm", "gem", "cargo", "go", "docker"]
skip = []
docker_contents = false

[cache]
ttl_hours = 24

[ui]
theme = "dark"         # Future: support light theme
```

---

## 10. Terminal UI (`ui/app.py`)

Build with **Textual** for the interactive mode. This gives a full-screen terminal app with mouse support, scrolling, keybindings.

### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡  VULNSCOPE v0.1.0          [Ubuntu 22.04 / kernel 6.5.0]  │
├────────┬────────┬────────┬────────┬────────────────────────────-┤
│ CRIT:3 │ HIGH:6 │ MED:5  │ LOW:2  │ Risk Score: 78/100         │
├────────┴────────┴────────┴────────┴────────────────────────────-┤
│ [Filter: All ▾] [Category: All ▾] [Sort: Severity ▾] [/search]│
├─────────────────────────────────────────────────────────────────┤
│ CVE ID          │ Package     │ Installed │ Fixed  │ Sev  │ KEV │
│─────────────────┼─────────────┼───────────┼────────┼──────┼─────│
│ CVE-2024-3094   │ xz-utils    │ 5.6.0     │ 5.6.2  │ CRIT │ ⚠️  │
│ CVE-2024-6387   │ openssh     │ 8.9p1     │ 9.7p1  │ CRIT │ ⚠️  │
│ CVE-2024-21626  │ runc        │ 1.1.10    │ 1.1.12 │ CRIT │    │
│ ...             │             │           │        │      │     │
├─────────────────────────────────────────────────────────────────┤
│ ▸ CVE-2024-3094 — XZ Utils Backdoor                 CVSS: 10.0 │
│   Malicious code injected into xz/liblzma allowing unauth...   │
│   Fix: sudo apt install xz-utils=5.6.2                         │
│   Refs: https://nvd.nist.gov/... | In CISA KEV (due 2024-04-) │
│                                                    [Copy fix ↗]│
└─────────────────────────────────────────────────────────────────┘
 q:quit  /:search  f:filter  s:sort  enter:expand  c:copy-fix  e:export
```

### Key Features
- **Live scan progress** with animated progress bar during scan phases
- **Sortable/filterable table** — arrow keys navigate, Enter expands detail
- **Detail panel** shows full description, CVSS breakdown, references, fix command
- **Copy fix command** to clipboard with `c` key
- **Export** from within the UI with `e` key (opens format picker)
- **KEV flag column** — instantly see which vulns are actively exploited

### Non-Interactive Mode (`--no-ui`)
Uses `rich` directly to print a formatted table and summary to stdout. Works in CI pipelines, log files, etc. Exit code: 0 = no vulns, 1 = vulns found (for CI gating).

---

## 11. Build & Test Plan

### Phase 1: Foundation (start here)
1. Set up `pyproject.toml`, project structure, `cli.py` with click
2. Implement `models.py` with all dataclasses
3. Implement `os_info.py` — parse `/etc/os-release`, `uname`
4. Implement `dpkg.py` as the first system collector (most common)
5. Implement `pip_packages.py` as the first language collector
6. Write tests with fixture data for both collectors

### Phase 2: Database Layer
7. Implement `osv.py` — batch query endpoint, response parsing
8. Implement `cache.py` — SQLite caching layer
9. Implement `matcher.py` — version comparison for SEMVER and ECOSYSTEM ranges
10. Implement `kev.py` — download and parse KEV catalog
11. Implement `nvd.py` — CPE-based OS/kernel queries, single CVE enrichment
12. Write tests with mocked API responses (use `respx` for httpx mocking)

### Phase 3: Full Inventory
13. Implement remaining collectors: `rpm.py`, `apk.py`, `npm_packages.py`, `gem_packages.py`, `cargo_packages.py`, `go_packages.py`
14. Implement `docker_images.py`
15. Implement `brew.py` for macOS support

### Phase 4: Scanner Pipeline
16. Implement `scanner.py` — full async orchestration pipeline
17. Wire up progress reporting
18. Implement deduplication logic (same CVE from OSV + NVD)
19. Integration test: run full scan on the dev machine

### Phase 5: UI
20. Implement `tables.py` — rich table output for `--no-ui` mode
21. Implement Textual app: main table view, severity header, keybindings
22. Implement detail panel with fix commands, references
23. Implement filter/sort/search within TUI

### Phase 6: Export & Polish
24. Implement JSON, CSV, SARIF, HTML exporters
25. Implement config file loading
26. CI exit codes (0 = clean, 1 = vulns found, 2 = error)
27. Write README with installation instructions, screenshots
28. Add `--severity` and `--ecosystem` filters to CLI

---

## 12. Key Technical Decisions & Gotchas

### PURL (Package URL) is the backbone
Every package gets a PURL. OSV accepts PURLs natively. This is the join key between inventory and vulnerability data. Use the format from https://github.com/package-url/purl-spec:
- `pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?arch=amd64`
- `pkg:pypi/requests@2.31.0`
- `pkg:npm/express@4.18.2`

### Version comparison is ecosystem-specific
Do NOT use a universal version comparator. Debian versions (`1:2.38-1ubuntu4`) are not semver. RPM versions have different rules. Always dispatch to the correct comparator based on ecosystem.

### OSV batch API is your best friend
One HTTP call can check 1000 packages. A typical machine has 1000-3000 packages. That's 1-3 API calls for the full scan. NVD would require thousands of individual calls.

### NVD rate limiting is harsh without an API key
5 requests per 30 seconds. Use NVD sparingly: only for OS/kernel CPE queries and enriching high/critical CVEs found via OSV. Always prompt the user to get a free NVD API key.

### Handle missing data gracefully
Not every CVE has a CVSS score. Not every vuln has a fix version. OSV might return a GHSA ID without a CVE alias. The UI and models must handle `None` everywhere.

### Debian/Ubuntu version → CVE matching is the hardest part
Ubuntu backports security fixes without bumping upstream versions. `openssl 3.0.2-0ubuntu1.15` might have CVE fixes that `3.0.2` proper doesn't. The OSV database for Debian/Ubuntu handles this correctly if you use the right PURL with the distro qualifier. Always include the distro in the PURL.

### Docker scanning is opt-in
Scanning inside Docker images is slow (requires running a container per image). Default off, behind a flag.

### Offline mode possibility
If APIs are unreachable, fall back to cache. If cache is empty, tell the user clearly rather than failing silently.

---

## 13. Example Run Flow

```
$ vulnscope scan

  🛡  VulnScope v0.1.0
  ─────────────────────

  ▸ Detecting system...    Ubuntu 22.04.4 LTS (kernel 6.5.0-44-generic)
  ▸ Inventorying packages...
    ├─ dpkg: 2,847 packages                                          ✓
    ├─ pip (3 environments): 312 packages                             ✓
    ├─ npm (global + 2 projects): 1,204 packages                     ✓
    ├─ gem: 48 packages                                               ✓
    ├─ cargo: 23 crates                                               ✓
    └─ docker: 6 images                                               ✓
  Total: 4,440 packages across 6 ecosystems

  ▸ Querying OSV.dev...        [████████████████████████████████] 5/5 batches
  ▸ Querying NVD (OS/kernel).. [████████████████████████████████] done
  ▸ Loading CISA KEV catalog.. 1,178 known exploited vulnerabilities loaded
  ▸ Cross-referencing...       done

  Scan complete in 8.3s — 23 vulnerabilities found

  [Interactive TUI launches here]
```

---

## 14. Future Extensions (out of scope for v0.1, but design for them)

- **Auto-fix mode**: `vulnscope fix CVE-2024-6387` runs the appropriate package manager update
- **Scheduled scans**: cron integration, diff against previous scan
- **Notification hooks**: Slack/email/webhook when new CVEs appear
- **SBOM generation**: Export CycloneDX or SPDX
- **Network service scanning**: Check for exposed services with known vulns
- **Windows support**: winget/chocolatey/scoop collectors
- **Compliance mapping**: Map CVEs to frameworks (PCI-DSS, SOC2, etc.)
