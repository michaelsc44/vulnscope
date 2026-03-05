import csv
import io

from vulnscope.models import ScanResult

COLUMNS = [
    "cve_id", "title", "severity", "cvss_score", "is_known_exploited",
    "kev_due_date", "package_name", "package_version", "package_ecosystem",
    "fixed_version", "published_date", "source", "references",
]


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS)
    writer.writeheader()

    for v in result.vulnerabilities:
        writer.writerow({
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity.value,
            "cvss_score": v.cvss_score or "",
            "is_known_exploited": v.is_known_exploited,
            "kev_due_date": v.kev_due_date or "",
            "package_name": v.affected_package.name,
            "package_version": v.affected_package.version,
            "package_ecosystem": v.affected_package.ecosystem,
            "fixed_version": v.fixed_version or "",
            "published_date": v.published_date or "",
            "source": v.source,
            "references": " | ".join(v.references[:3]),
        })

    return buf.getvalue()
