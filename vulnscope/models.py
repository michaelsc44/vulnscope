from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class InstalledPackage:
    name: str
    version: str
    ecosystem: str  # "deb", "rpm", "pypi", "npm", "cargo", "apk", "docker"
    source: str  # e.g. "dpkg", "pip3", "npm-global"
    arch: str | None
    purl: str  # Package URL e.g. pkg:deb/ubuntu/openssl@3.0.2?arch=amd64


@dataclass
class Vulnerability:
    cve_id: str  # "CVE-2024-6387" or OSV ID if no CVE alias
    aliases: list[str]  # ["GHSA-xxxx", "RUSTSEC-2024-..."]
    title: str
    description: str
    severity: Severity
    cvss_score: float | None  # 0.0 - 10.0
    cvss_vector: str | None  # "CVSS:3.1/AV:N/AC:L/..."
    cwe_ids: list[str]  # ["CWE-362"]
    affected_package: InstalledPackage
    fixed_version: str | None
    is_known_exploited: bool
    kev_due_date: str | None
    references: list[str]
    published_date: str | None
    source: str  # "osv", "nvd"


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str  # ISO 8601
    os_info: dict
    total_packages: int
    vulnerabilities: list[Vulnerability]
    scan_duration_seconds: float

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """Weighted aggregate score 0-100."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.UNKNOWN: 1,
        }
        kev_bonus = 5
        raw = 0
        for v in self.vulnerabilities:
            raw += weights[v.severity]
            if v.is_known_exploited:
                raw += kev_bonus
        return min(100, raw)


@dataclass
class ScanConfig:
    ecosystems: list[str] = field(default_factory=lambda: ["os", "deb", "rpm", "pypi", "npm", "cargo", "apk"])
    skip: list[str] = field(default_factory=list)
    no_cache: bool = False
    scan_docker_contents: bool = False
    severity_filter: str | None = None
    nvd_api_key: str | None = None
    cache_ttl_hours: int = 24


@dataclass
class ScanProgress:
    phase: str
    detail: str
    percent: float  # 0.0 - 100.0
