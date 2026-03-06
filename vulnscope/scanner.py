import asyncio
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from vulnscope.config import CACHE_DIR
from vulnscope.databases.cache import CacheDB
from vulnscope.databases.kev import load_kev_catalog
from vulnscope.databases.nvd import NvdClient
from vulnscope.databases.osv import query_osv_batch
from vulnscope.inventory.apk import ApkCollector
from vulnscope.inventory.cargo_packages import CargoCollector
from vulnscope.inventory.docker_images import DockerCollector
from vulnscope.inventory.dpkg import DpkgCollector
from vulnscope.inventory.flatpak import FlatpakCollector
from vulnscope.inventory.npm_packages import NpmCollector
from vulnscope.inventory.os_info import OSInfo, get_os_info
from vulnscope.inventory.pip_packages import PipCollector
from vulnscope.inventory.rpm import RpmCollector
from vulnscope.inventory.snap import SnapCollector
from vulnscope.models import (
    InstalledPackage,
    ScanConfig,
    ScanProgress,
    ScanResult,
    Severity,
    Vulnerability,
)

ProgressCallback = Callable[[ScanProgress], None]


def _deduplicate_packages(packages: list[InstalledPackage]) -> list[InstalledPackage]:
    seen: dict[str, InstalledPackage] = {}
    for pkg in packages:
        key = f"{pkg.ecosystem}:{pkg.name.lower()}@{pkg.version}"
        if key not in seen:
            seen[key] = pkg
    return list(seen.values())


def _deduplicate_vulns(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    """Deduplicate by CVE ID + package name, merging NVD enrichment into OSV entries."""
    seen: dict[str, Vulnerability] = {}
    for v in vulnerabilities:
        key = f"{v.cve_id}:{v.affected_package.name}:{v.affected_package.version}"
        if key not in seen:
            seen[key] = v
        else:
            existing = seen[key]
            # Prefer NVD CVSS data over OSV when available
            if v.source == "nvd" and existing.source == "osv":
                seen[key] = Vulnerability(
                    cve_id=existing.cve_id,
                    aliases=existing.aliases or v.aliases,
                    title=existing.title,
                    description=existing.description or v.description,
                    severity=v.severity if v.severity != Severity.UNKNOWN else existing.severity,
                    cvss_score=v.cvss_score if v.cvss_score is not None else existing.cvss_score,
                    cvss_vector=v.cvss_vector or existing.cvss_vector,
                    cwe_ids=v.cwe_ids or existing.cwe_ids,
                    affected_package=existing.affected_package,
                    fixed_version=existing.fixed_version or v.fixed_version,
                    is_known_exploited=existing.is_known_exploited,
                    kev_due_date=existing.kev_due_date,
                    references=list(set(existing.references + v.references)),
                    published_date=existing.published_date or v.published_date,
                    source="osv+nvd",
                )
    return list(seen.values())


def _sort_vulnerabilities(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.UNKNOWN: 4,
    }

    def sort_key(v: Vulnerability) -> tuple:
        kev_priority = 0 if v.is_known_exploited else 1
        return (sev_order[v.severity], kev_priority, -(v.cvss_score or 0.0))

    return sorted(vulnerabilities, key=sort_key)


def _enrich_with_kev(
    vulnerabilities: list[Vulnerability],
    kev_catalog: dict[str, dict],
) -> list[Vulnerability]:
    enriched = []
    for v in vulnerabilities:
        if v.cve_id in kev_catalog:
            entry = kev_catalog[v.cve_id]
            enriched.append(
                Vulnerability(
                    cve_id=v.cve_id,
                    aliases=v.aliases,
                    title=v.title,
                    description=v.description,
                    severity=v.severity,
                    cvss_score=v.cvss_score,
                    cvss_vector=v.cvss_vector,
                    cwe_ids=v.cwe_ids,
                    affected_package=v.affected_package,
                    fixed_version=v.fixed_version,
                    is_known_exploited=True,
                    kev_due_date=entry.get("dueDate"),
                    references=v.references,
                    published_date=v.published_date,
                    source=v.source,
                )
            )
        else:
            enriched.append(v)
    return enriched


async def run_scan(
    config: ScanConfig,
    progress_cb: ProgressCallback | None = None,
) -> ScanResult:
    start_time = datetime.now(timezone.utc)

    def _progress(phase: str, detail: str, percent: float) -> None:
        if progress_cb:
            progress_cb(ScanProgress(phase=phase, detail=detail, percent=percent))

    # Phase 1: OS info
    _progress("inventory", "Detecting operating system...", 5)
    loop = asyncio.get_event_loop()
    os_info: OSInfo = await loop.run_in_executor(None, get_os_info)

    # Phase 2: Collect packages in parallel threads
    _progress("inventory", "Collecting installed packages...", 10)
    collectors = []
    active_ecosystems = set(config.ecosystems) - set(config.skip)

    if "deb" in active_ecosystems:
        collectors.append(DpkgCollector(distro_id=os_info.id))
    if "rpm" in active_ecosystems:
        collectors.append(RpmCollector(distro_id=os_info.id))
    if "apk" in active_ecosystems:
        collectors.append(ApkCollector())
    if "pypi" in active_ecosystems:
        collectors.append(PipCollector())
    if "npm" in active_ecosystems:
        collectors.append(NpmCollector())
    if "cargo" in active_ecosystems:
        collectors.append(CargoCollector())
    if "docker" in active_ecosystems:
        collectors.append(DockerCollector(scan_contents=config.scan_docker_contents))
    if "snap" in active_ecosystems or "snap" not in config.skip:
        collectors.append(SnapCollector())
    if "flatpak" in active_ecosystems:
        collectors.append(FlatpakCollector())

    def _run_collector(collector):
        if not collector.is_available():
            return []
        return collector.collect()

    all_packages: list[InstalledPackage] = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [loop.run_in_executor(executor, _run_collector, c) for c in collectors]
        results = await asyncio.gather(*futures)
        for pkgs in results:
            all_packages.extend(pkgs)

    all_packages = _deduplicate_packages(all_packages)
    _progress("inventory", f"Found {len(all_packages)} packages", 25)

    # Phase 3: Set up cache
    cache: CacheDB | None = None
    if not config.no_cache:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache = CacheDB(ttl_hours=config.cache_ttl_hours)

    # Phase 4: Query OSV
    _progress("osv", "Querying OSV.dev for vulnerabilities...", 30)

    def osv_progress(done: int, total: int) -> None:
        pct = 30 + (done / max(total, 1)) * 30
        _progress("osv", f"OSV batch {done}/{total}", pct)

    vulnerabilities = await query_osv_batch(
        all_packages,
        cache=cache,
        no_cache=config.no_cache,
        progress_cb=osv_progress,
    )
    _progress("osv", f"OSV: {len(vulnerabilities)} potential vulnerabilities", 60)

    # Phase 5: NVD OS/kernel queries
    _progress("nvd", "Querying NVD for OS/kernel CVEs...", 62)
    nvd_client = NvdClient(api_key=config.nvd_api_key, cache=cache)

    if "os" in active_ecosystems:
        os_package = InstalledPackage(
            name=os_info.id,
            version=os_info.version,
            ecosystem="os",
            source="os-release",
            arch=os_info.arch,
            purl=f"pkg:generic/{os_info.id}@{os_info.version}",
        )
        try:
            nvd_os_vulns = await nvd_client.query_os_cves(
                os_info=os_info,
                os_package=os_package,
                no_cache=config.no_cache,
            )
            vulnerabilities.extend(nvd_os_vulns)
        except Exception:
            pass

    _progress("nvd", "NVD queries complete", 67)

    # Phase 5b: NVD application CPE queries (Chrome, Firefox, VS Code, etc.)
    _progress("nvd", "Querying NVD for installed applications (Chrome, Firefox…)...", 68)
    try:
        nvd_app_vulns = await nvd_client.query_app_cves(
            all_packages,
            no_cache=config.no_cache,
        )
        vulnerabilities.extend(nvd_app_vulns)
        _progress("nvd", f"NVD apps: {len(nvd_app_vulns)} application vulnerabilities found", 70)
    except Exception:
        pass

    _progress("nvd", "NVD queries complete", 71)

    # Phase 6: Load CISA KEV catalog
    _progress("kev", "Loading CISA KEV catalog...", 72)
    try:
        kev_catalog = await load_kev_catalog(cache=cache, no_cache=config.no_cache)
    except Exception:
        kev_catalog = {}
    _progress("kev", f"KEV: {len(kev_catalog)} known exploited CVEs loaded", 78)

    # Phase 7: Enrich with KEV data
    _progress("enrich", "Cross-referencing KEV...", 80)
    vulnerabilities = _enrich_with_kev(vulnerabilities, kev_catalog)

    # Phase 8: NVD enrichment for CRITICAL/HIGH
    _progress("enrich", "Enriching critical/high CVEs with NVD CVSS data...", 83)
    try:
        vulnerabilities = await nvd_client.enrich_vulnerabilities(
            vulnerabilities,
            no_cache=config.no_cache,
        )
    except Exception:
        pass

    # Phase 9: Deduplicate
    _progress("dedup", "Deduplicating results...", 90)
    vulnerabilities = _deduplicate_vulns(vulnerabilities)

    # Phase 10: Sort
    vulnerabilities = _sort_vulnerabilities(vulnerabilities)

    # Apply severity filter
    if config.severity_filter:
        sev_order = ["critical", "high", "medium", "low", "unknown"]
        threshold_idx = sev_order.index(config.severity_filter.lower())
        allowed = set(sev_order[: threshold_idx + 1])
        vulnerabilities = [v for v in vulnerabilities if v.severity.value in allowed]

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    _progress("complete", f"Scan complete: {len(vulnerabilities)} vulnerabilities found", 100)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        timestamp=start_time.isoformat(),
        os_info=os_info.to_dict(),
        total_packages=len(all_packages),
        vulnerabilities=vulnerabilities,
        scan_duration_seconds=duration,
    )
