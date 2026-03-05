import json

from vulnscope.models import ScanResult, Vulnerability


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


def to_json(result: ScanResult, indent: int = 2) -> str:
    data = {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp,
        "os_info": result.os_info,
        "total_packages": result.total_packages,
        "scan_duration_seconds": result.scan_duration_seconds,
        "summary": {
            "total_vulnerabilities": len(result.vulnerabilities),
            "risk_score": result.risk_score,
            "counts_by_severity": {k.value: v for k, v in result.counts_by_severity.items()},
        },
        "vulnerabilities": [_vuln_to_dict(v) for v in result.vulnerabilities],
    }
    return json.dumps(data, indent=indent, default=str)
