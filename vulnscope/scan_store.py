"""Persist scan results and diff against previous scans."""

from __future__ import annotations

import json
from pathlib import Path

from platformdirs import user_data_dir

from vulnscope.models import (
    InstalledPackage,
    ScanResult,
    Severity,
    Vulnerability,
)

DATA_DIR = Path(user_data_dir("vulnscope", ensure_exists=True))
SCANS_DIR = DATA_DIR / "scans"


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "cve_id": v.cve_id,
        "aliases": v.aliases,
        "title": v.title,
        "description": v.description,
        "severity": v.severity.value,
        "cvss_score": v.cvss_score,
        "cvss_vector": v.cvss_vector,
        "cwe_ids": v.cwe_ids,
        "affected_package": {
            "name": v.affected_package.name,
            "version": v.affected_package.version,
            "ecosystem": v.affected_package.ecosystem,
            "source": v.affected_package.source,
            "arch": v.affected_package.arch,
            "purl": v.affected_package.purl,
        },
        "fixed_version": v.fixed_version,
        "is_known_exploited": v.is_known_exploited,
        "kev_due_date": v.kev_due_date,
        "references": v.references,
        "published_date": v.published_date,
        "source": v.source,
    }


def _vuln_from_dict(d: dict) -> Vulnerability:
    pkg = d["affected_package"]
    return Vulnerability(
        cve_id=d["cve_id"],
        aliases=d.get("aliases", []),
        title=d.get("title", ""),
        description=d.get("description", ""),
        severity=Severity(d.get("severity", "unknown")),
        cvss_score=d.get("cvss_score"),
        cvss_vector=d.get("cvss_vector"),
        cwe_ids=d.get("cwe_ids", []),
        affected_package=InstalledPackage(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem=pkg["ecosystem"],
            source=pkg["source"],
            arch=pkg.get("arch"),
            purl=pkg["purl"],
        ),
        fixed_version=d.get("fixed_version"),
        is_known_exploited=d.get("is_known_exploited", False),
        kev_due_date=d.get("kev_due_date"),
        references=d.get("references", []),
        published_date=d.get("published_date"),
        source=d.get("source", "unknown"),
    )


def result_to_dict(result: ScanResult) -> dict:
    return {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp,
        "os_info": result.os_info,
        "total_packages": result.total_packages,
        "scan_duration_seconds": result.scan_duration_seconds,
        "vulnerabilities": [_vuln_to_dict(v) for v in result.vulnerabilities],
    }


def result_from_dict(data: dict) -> ScanResult:
    return ScanResult(
        scan_id=data["scan_id"],
        timestamp=data["timestamp"],
        os_info=data.get("os_info", {}),
        total_packages=data.get("total_packages", 0),
        vulnerabilities=[_vuln_from_dict(v) for v in data.get("vulnerabilities", [])],
        scan_duration_seconds=data.get("scan_duration_seconds", 0.0),
    )


def save_scan(result: ScanResult) -> Path:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    ts = result.timestamp.replace(":", "-").replace("+", "_")
    filepath = SCANS_DIR / f"scan_{ts}.json"
    filepath.write_text(json.dumps(result_to_dict(result), indent=2, default=str))
    return filepath


def load_latest_scan() -> ScanResult | None:
    if not SCANS_DIR.exists():
        return None
    scans = sorted(SCANS_DIR.glob("scan_*.json"))
    if not scans:
        return None
    data = json.loads(scans[-1].read_text())
    return result_from_dict(data)


def diff_scans(previous: ScanResult, current: ScanResult) -> list[Vulnerability]:
    """Return vulnerabilities in current that were NOT in previous."""
    prev_cves = {(v.cve_id, v.affected_package.name) for v in previous.vulnerabilities}
    return [
        v for v in current.vulnerabilities
        if (v.cve_id, v.affected_package.name) not in prev_cves
    ]
