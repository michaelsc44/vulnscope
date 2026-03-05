"""SARIF 2.1.0 export for GitHub Advanced Security and CI integration."""

import json

from vulnscope import __version__
from vulnscope.models import ScanResult, Severity, Vulnerability

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}


def _vuln_to_rule(v: Vulnerability) -> dict:
    return {
        "id": v.cve_id,
        "name": v.cve_id.replace("-", ""),
        "shortDescription": {"text": v.title or v.cve_id},
        "fullDescription": {"text": v.description or v.title or v.cve_id},
        "helpUri": v.references[0] if v.references else f"https://nvd.nist.gov/vuln/detail/{v.cve_id}",
        "properties": {
            "tags": ["vulnerability", "security", v.severity.value],
            "security-severity": str(v.cvss_score) if v.cvss_score else "5.0",
        },
    }


def _vuln_to_result(v: Vulnerability, rule_index: int) -> dict:
    level = LEVEL_MAP.get(v.severity, "note")
    message = f"{v.cve_id} in {v.affected_package.name}@{v.affected_package.version}"
    if v.fixed_version:
        message += f" — fixed in {v.fixed_version}"
    if v.is_known_exploited:
        message += " (CISA KEV: actively exploited)"

    return {
        "ruleId": v.cve_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"package/{v.affected_package.ecosystem}/{v.affected_package.name}",
                        "uriBaseId": "%SRCROOT%",
                    }
                },
                "logicalLocations": [
                    {
                        "name": v.affected_package.name,
                        "kind": "package",
                        "fullyQualifiedName": v.affected_package.purl,
                    }
                ],
            }
        ],
        "properties": {
            "cvssScore": v.cvss_score,
            "isKnownExploited": v.is_known_exploited,
            "fixedVersion": v.fixed_version,
        },
    }


def to_sarif(result: ScanResult) -> str:
    seen_rules: dict[str, int] = {}
    rules = []
    results = []

    for v in result.vulnerabilities:
        if v.cve_id not in seen_rules:
            seen_rules[v.cve_id] = len(rules)
            rules.append(_vuln_to_rule(v))
        rule_index = seen_rules[v.cve_id]
        results.append(_vuln_to_result(v, rule_index))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscope",
                        "version": __version__,
                        "informationUri": "https://github.com/michaelsc44/vulnscope",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scanId": result.scan_id,
                    "timestamp": result.timestamp,
                    "totalPackages": result.total_packages,
                    "riskScore": result.risk_score,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)
