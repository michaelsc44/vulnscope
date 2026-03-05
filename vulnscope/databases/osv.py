import asyncio
from collections.abc import Callable

import httpx

from vulnscope.databases.cache import CacheDB
from vulnscope.matcher import is_affected
from vulnscope.models import InstalledPackage, Severity, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 1000


def _parse_severity(osv_severity: list[dict] | None, cvss_score: float | None) -> Severity:
    if osv_severity:
        for sev in osv_severity:
            score_str = sev.get("score", "")
            if "CRITICAL" in score_str.upper():
                return Severity.CRITICAL
            if "HIGH" in score_str.upper():
                return Severity.HIGH
            if "MEDIUM" in score_str.upper():
                return Severity.MEDIUM
            if "LOW" in score_str.upper():
                return Severity.LOW
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        if cvss_score >= 7.0:
            return Severity.HIGH
        if cvss_score >= 4.0:
            return Severity.MEDIUM
        if cvss_score > 0.0:
            return Severity.LOW
    return Severity.UNKNOWN


def _extract_cvss(osv_vuln: dict) -> tuple[float | None, str | None]:
    for sev in osv_vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V31"):
            vector = sev.get("score", "")
            if vector:
                try:
                    parts = vector.split("/")
                    base = float(parts[-1]) if parts[-1].replace(".", "").isdigit() else None
                    return base, vector
                except (ValueError, IndexError):
                    pass
    return None, None


def _get_cve_id(osv_vuln: dict) -> str:
    osv_id = osv_vuln.get("id", "")
    for alias in osv_vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return osv_id


def _get_fixed_version(affected: list[dict]) -> str | None:
    for entry in affected:
        for r in entry.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _parse_osv_vuln(osv_vuln: dict, package: InstalledPackage) -> Vulnerability | None:
    affected = osv_vuln.get("affected", [])
    if not affected:
        return None

    ranges_list = []
    for entry in affected:
        ranges_list.extend(entry.get("ranges", []))
        versions = entry.get("versions", [])
        if versions:
            ranges_list.append({"type": "EXACT", "versions": versions})

    if ranges_list and not is_affected(package.version, ranges_list, package.ecosystem):
        return None

    cvss_score, cvss_vector = _extract_cvss(osv_vuln)
    severity = _parse_severity(osv_vuln.get("severity"), cvss_score)
    cve_id = _get_cve_id(osv_vuln)
    aliases = [a for a in osv_vuln.get("aliases", []) if a != cve_id]

    refs = [r.get("url", "") for r in osv_vuln.get("references", []) if r.get("url")]

    return Vulnerability(
        cve_id=cve_id,
        aliases=aliases,
        title=osv_vuln.get("summary", cve_id),
        description=osv_vuln.get("details", ""),
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_ids=[],
        affected_package=package,
        fixed_version=_get_fixed_version(affected),
        is_known_exploited=False,
        kev_due_date=None,
        references=refs,
        published_date=osv_vuln.get("published"),
        source="osv",
    )


async def query_osv_batch(
    packages: list[InstalledPackage],
    cache: CacheDB | None = None,
    no_cache: bool = False,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []

    uncached: list[InstalledPackage] = []
    cached_results: dict[str, list[dict]] = {}

    if cache and not no_cache:
        for pkg in packages:
            data = cache.get_osv(pkg.purl)
            if data is not None:
                cached_results[pkg.purl] = data.get("vulns", [])
            else:
                uncached.append(pkg)
    else:
        uncached = list(packages)

    for purl, vulns in cached_results.items():
        pkg = next((p for p in packages if p.purl == purl), None)
        if pkg:
            for v in vulns:
                parsed = _parse_osv_vuln(v, pkg)
                if parsed:
                    vulnerabilities.append(parsed)

    if not uncached:
        return vulnerabilities

    batches = [uncached[i : i + BATCH_SIZE] for i in range(0, len(uncached), BATCH_SIZE)]
    total_batches = len(batches)

    async with httpx.AsyncClient(timeout=60.0) as client:
        for batch_idx, batch in enumerate(batches):
            queries = [{"package": {"purl": pkg.purl}} for pkg in batch]
            payload = {"queries": queries}

            try:
                resp = await client.post(OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError:
                if progress_cb:
                    progress_cb(batch_idx + 1, total_batches)
                continue

            results = data.get("results", [])
            for i, result in enumerate(results):
                if i >= len(batch):
                    break
                pkg = batch[i]
                vulns = result.get("vulns", [])

                if cache and not no_cache:
                    cache.set_osv(pkg.purl, {"vulns": vulns})

                for v in vulns:
                    parsed = _parse_osv_vuln(v, pkg)
                    if parsed:
                        vulnerabilities.append(parsed)

            if progress_cb:
                progress_cb(batch_idx + 1, total_batches)

            if batch_idx < total_batches - 1:
                await asyncio.sleep(0.5)

    return vulnerabilities
